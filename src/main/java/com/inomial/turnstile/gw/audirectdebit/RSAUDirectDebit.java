package com.inomial.turnstile.gw.audirectdebit;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.inomial.cim.turnstile.AUBankAccountDetails;
import com.inomial.cim.turnstile.DirectDebitPaymentRequest;
import com.inomial.cim.turnstile.PaymentStatus;
import com.inomial.secore.kafka.KafkaMessage;
import com.inomial.secore.kafka.MessageProducer;
import com.inomial.secore.scope.RequestScope;
import com.inomial.turnstile.api.status.CaptureStatus;
import com.inomial.turnstile.gw.common.ConfigUnmarshaller;
import com.inomial.turnstile.gw.common.ParseUtil;
import com.inomial.turnstile.gw.common.Results;
import com.inomial.turnstile.gw.common.URLInterpolator;
import com.inomial.turnstile.gw.common.ValidationHelper;
import com.inomial.turnstile.gw.spi.CaptureQueryRequest;
import com.inomial.turnstile.gw.spi.CaptureResult;
import com.inomial.turnstile.gw.spi.CnpTransferRequest;
import com.inomial.turnstile.gw.spi.CppQueryRequest;
import com.inomial.turnstile.gw.spi.CppTransferRequest;
import com.inomial.turnstile.gw.spi.DeleteTokenRequest;
import com.inomial.turnstile.gw.spi.DeleteTokenResult;
import com.inomial.turnstile.gw.spi.DeleteTokenResult.DeleteTokenStatus;
import com.inomial.turnstile.gw.spi.TokeniseRequest;
import com.inomial.turnstile.gw.spi.TransferResult;
import com.inomial.turnstile.gw.spi.TurnstileGateway;
import com.inomial.turnstile.gw.spi.WebFormResult;
import com.inomial.turnstile.gw.spi.WebFormResult.WebFormStatus;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.lf5.LogLevel;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Context;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.logging.Logger;

/** Australia Direct Debit gateway for Turnstile.
@author wniu */
public class RSAUDirectDebit extends Application implements TurnstileGateway
{
  private static Logger log = Logger.getLogger(RSAUDirectDebit.class.getName());

  private static final ObjectMapper objectMapper = new ObjectMapper();

  /** <code>{gw}</code> substitution code for this gateway */
  private static final String GW = "audirectdebit";

  /** Default web form submission timeout, in seconds. */
  private static final int DEFAULT_WEB_FORM_TIMEOUT_SEC = 900; // 15min

  /** Version number of Kafka messages that we generate */
  private static final int INOMIAL_MESSAGE_VERSION = 1;

  /** Kakfa Topic that payment request messages are sent on */
  private static final String PAYMENT_REQUEST_TOPIC = "petal.event";

  /** Message source that we'll post Kafka messages as */
  private static final String KAFKA_MESSAGE_SOURCE = "turnstile-audirectdebit-gw";

  @Context
  private HttpServletRequest httpServletRequest;

  @JsonIgnoreProperties(ignoreUnknown=true)
  static class Config
  {
    @JsonPropertyDescription("Petal institution ID")
    @JsonProperty(required=true)
    @JsonSetter(nulls=Nulls.FAIL)
    public int institution;

    @JsonPropertyDescription("URL template for self-hosted card capture page")
    @JsonProperty(required=true)
    @JsonSetter(nulls=Nulls.FAIL)
    public String tokenCaptureUrl;

    @JsonPropertyDescription("Web form data entry timeout, in seconds.")
    public int webFormTimeoutSec = DEFAULT_WEB_FORM_TIMEOUT_SEC;
  }



  @Override
  public WebFormResult getCPPaymentUrl(CppTransferRequest transferRequest)
  {
    return Results.webFormFailed(WebFormStatus.OPERATION_NOT_SUPPORTED,
      "Card-present payments are not implemented in turnstile-audirectdebit-gw.");
  }

  @Override
  public TransferResult queryPaymentStatus(CppQueryRequest queryRequest)
  {
    return Results.transferFailed(PaymentStatus.OPERATION_NOT_SUPPORTED,
      "Card-present payments are not implemented in turnstile-audirectdebit-gw.");
  }

  @Override
  public WebFormResult getCaptureUrl(TokeniseRequest tokeniseRequest)
  {
    return RequestScope.enterScope(httpServletRequest, () -> 
    {
      log.info("Received request for card capture URL: tid=" + RequestScope.getTid() 
        + ", tokeniseRequest=" + tokeniseRequest);
      ValidationHelper.validateGetCaptureUrlArgs(tokeniseRequest);
      Config config = ConfigUnmarshaller.unmarshal(tokeniseRequest, Config.class);
      
      // Ensure that only the end-user that requested this form can be the one that submits the token to us.
      WebFormMac.HmacTimestamp authMac = WebFormMac.createCaptureFormHmac(tokeniseRequest);
      
      String redirectUrl = URLInterpolator.forCardCaptureUrl(config.tokenCaptureUrl, GW, httpServletRequest)
        .addQueryArg("hmac", authMac.hmac)
        .addQueryArg("fct", authMac.formCreationTime.toEpochMilli())
        .addQueryArgIfNotNull("prevStatus", tokeniseRequest.prevStatus)
        .addBase64QueryArg("action", tokeniseRequest.returnUrl)
        .render();
      log.info("Redirecting to self-hosted card present payment page at: " + redirectUrl);
          
      return Results.webFormSuccess(redirectUrl);
    });
  }

  @Override
  public CaptureResult queryCardCapture(CaptureQueryRequest queryRequest)
  {
    return RequestScope.enterScope(httpServletRequest, () ->
    {
      log.info("Looking up card capture result for: tid=" + RequestScope.getTid() + ", queryRequest=" + queryRequest);
      ValidationHelper.validateQueryCardCaptureArgs(queryRequest);
      Config config = ConfigUnmarshaller.unmarshal(queryRequest, Config.class);
      
      // Validate inbound HMAC
      String expectedHmac = ParseUtil.getQueryArgValue(queryRequest.urlQueryString, "hmac");
      Instant formCreationTime = Instant.ofEpochMilli(ParseUtil.getLongQueryArg(queryRequest.urlQueryString, "fct"));
      if (Instant.now().isAfter(formCreationTime.plus(config.webFormTimeoutSec, ChronoUnit.SECONDS)))
        return Results.captureFailed(CaptureStatus.TIMED_OUT,
          "Web form timed out (" + config.webFormTimeoutSec + " seconds)");
      if (!WebFormMac.verifyCaptureFormHmac(expectedHmac, queryRequest, formCreationTime))
        return Results.captureFailed(CaptureStatus.INVALID_REQUEST, "HMAC validation failure");
      
      // Request has been verified as authentic - ensure that the account number is a valid AU bank account number.
      AUBankAccountDetails bankAcct = new AUBankAccountDetails();
      bankAcct.name = ParseUtil.getQueryArgValue(queryRequest.urlQueryString, "name");
      bankAcct.account = ParseUtil.getQueryArgValue(queryRequest.urlQueryString, "bsb")
              + ParseUtil.getQueryArgValue(queryRequest.urlQueryString, "account");

      // Pass AUBankAccountDetails as a JSON String with key and token type to encrypt at Turnstile
      CaptureResult result = new CaptureResult();
      result.token = objectMapper.writeValueAsString(bankAcct);
      result.key = String.valueOf(config.institution);
      result.expiryDate = null;
      result.hint = toHint(bankAcct.account);
      result.status = CaptureStatus.ACCEPTED;
      
      return result;
    });
  }

  @Override
  public TransferResult cnpTransfer(CnpTransferRequest transferRequest)
  {
    //to do : VIE-324
    return Results.transferFailed(PaymentStatus.OPERATION_NOT_SUPPORTED,
            "Direct Debit payments are not implemented in turnstile-audirectdebit-gw.");
  }

  @Override
  public DeleteTokenResult deleteToken(DeleteTokenRequest deleteTokenRequest)
  {
    return Results.deleteTokenFailed(DeleteTokenStatus.OPERATION_NOT_SUPPORTED,
        "Token deletion is yet to be implemented in turnstile-audirectdebit-gw");
  }

  private String toHint(String account)
  {

    int len = account.length();
    if (len < 12) {
      throw new IllegalArgumentException("AU account number should not be less than 12 digits.");
    }
    // Want first 3 digits and last 3 digits, with Xs filling in the missing bits
    return account.substring(0, 3) + StringUtils.repeat("X",len - 6) + account.substring(len - 3);
  }
}