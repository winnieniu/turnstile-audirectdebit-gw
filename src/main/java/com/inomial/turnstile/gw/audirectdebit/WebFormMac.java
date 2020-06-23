package com.inomial.turnstile.gw.audirectdebit;

import com.inomial.secore.scope.RequestScope;
import com.inomial.turnstile.gw.common.HmacUtil;
import com.inomial.turnstile.gw.common.HmacUtil.MacSerialisers;
import com.inomial.turnstile.gw.common.HmacUtil.MessageSerialisers;
import com.inomial.turnstile.gw.spi.CaptureQueryRequest;
import com.inomial.turnstile.gw.spi.GatewayRequest;
import com.inomial.turnstile.gw.spi.TokeniseRequest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.ws.rs.InternalServerErrorException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Routines used for ensuring security of the web form entry for the AU Direct Debit gateway by computing a MAC
 * (message authentication code); in this particular case a RFC2104-style HMAC.
 * 
 * <p>This is to ensure that the end-user that requested a webform is the same end-user that submits the account capture
 * details, while allowing the AU Direct Debit gateway microservice to remain stateless. It's also used to enforce a
 * timeout on the forms (to reduce the potential window for token-stealing or spoofing attacks).</p>
 * 
 * @author bryan */
class WebFormMac
{
  private static final Logger log = Logger.getLogger(WebFormMac.class.getName());

  /** Web form MAC key file location. This file must contain the actual binary secret. */
  private static final File SECRET_FILE = new File(
    System.getenv().getOrDefault("WEBFORMMAC_SECRET",
      "/run/secrets/turnstile-audirectdebit-gw_webformmac_secret"));
  
  /** MAC algorithm to use for computing MAC (Message Authentication Code) for securing web forms.
   * <p>Must be a valid <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac">
   * Java Cryptography Architecture Standard Mac Algorithm Name</a>. */
  private static final String SECRET_ALGORITHM =
      System.getenv().getOrDefault("WEBFORMMAC_ALGORITHM", "HmacSHA256");

  /** Contains an HMAC-timestamp pair for a web form creation; the HMAC is computed over the security-sensitive
   * parameters of the form (including the timestamp), and the timestamp is made separately available so it can be
   * used to recompute the HMAC when verifiying it. */
  static class HmacTimestamp
  {
    public String hmac;
    public Instant formCreationTime;
    
    HmacTimestamp()
    {
      // This constructor intentionally left empty
    }
    
    HmacTimestamp(String hmac, Instant formCreationTime)
    {
      this.hmac = hmac;
      this.formCreationTime = formCreationTime;
    }

    @Override
    public String toString()
    {
      StringBuilder builder = new StringBuilder();
      builder.append("HmacTimestamp [hmac=");
      builder.append(hmac);
      builder.append(", formCreationTime=");
      builder.append(formCreationTime);
      builder.append("]");
      return builder.toString();
    }
  }
  
  /** Base class of HMAC message body produced when a web form is requested 
   * 
   * <p>Whenever a web form URL is created for the end-user, the contents of this structure will be serialised and
   * signed to produce a HMAC that is used to enforce that the card token must be returned via the same IP address and
   * logged-in principal that the web form redirect was sent to, when the end-user calls back into Turnstile to
   * conclude the transaction.</p>
   * 
   * <p>This is an attempt to mitigate the limitation in PIN Payments' API where it is not possible to discern which
   * customer a card token actually belongs to (which can make us vulnerable to token substitution attacks).</p>
   * 
   * <p>Note that these classes only need to be <em>serialisable</em>; there's no need for them to be
   * <em>deserialisable</em>. The {@code final} modifier helps catch fields that aren't being initialised, which
   * could lead to HMAC validation errors. */
  private static abstract class WebFormAuthorisation implements Serializable
  {
    private static final long serialVersionUID = -5279064092554681202L;

    /** Use this constructor when verifying against a previous HMAC */
    protected WebFormAuthorisation(int tid, UUID principal, GatewayRequest req, Instant formCreationTime)
    {
      this.tid = tid;
      this.principal = principal;
      this.endUserIpAddress = req.endUserIpAddress;
      this.accountId = req.accountId;
      this.formCreationTime = formCreationTime;
    }
    
    /** Use this constructor when creating a new HMAC */
    protected WebFormAuthorisation(int tid, UUID principal, GatewayRequest req)
    {
      this(tid, principal, req, Instant.now().truncatedTo(ChronoUnit.MILLIS));
    }

    /** Tenant ID that request was made under */
    public final int tid;
    /** Logged-in Keycloak principal that the payment was being made under */
    public final UUID principal;
    /** The IP address of the end-user that originally requested this form. */
    public final InetAddress endUserIpAddress;
    /** Account UUID that the payment is being made for */
    public final UUID accountId;
    /** Timestamp when the web form was issued; deters replay attacks if we expire webforms after a certain time limit.
     * The timestamp must be passed to the end-user and back so we can reconstruct the original message.
     * Must be of no finer than millisecond precision. */
    public final Instant formCreationTime;
    
    // Operation-specific fields will follow hereon in subclasses.
  }
  
  /** HMAC message body used when signing a token-capture web form request. */
  private static class CaptureFormAuthorisation extends WebFormAuthorisation
  {
    private static final long serialVersionUID = 5679156574001177919L;

    /** Use this constructor when creating a new HMAC */
    CaptureFormAuthorisation(int tid, UUID principal, TokeniseRequest req)
    {
      super(tid, principal, req);
      this.paymentMethodId = req.paymentMethodId;
    }
    
    /** Use this constructor when verifying against a previous HMAC */
    CaptureFormAuthorisation(int tid, UUID principal, CaptureQueryRequest req, Instant formCreationTime)
    {
      super(tid, principal, req, formCreationTime);
      this.paymentMethodId = req.paymentMethodId;
    }

    /** Payment method that the capture is being performed for */
    public final UUID paymentMethodId;

    @Override
    public String toString()
    {
      StringBuilder builder = new StringBuilder();
      builder.append("CaptureFormAuthorisation [paymentMethodId=");
      builder.append(paymentMethodId);
      builder.append(", tid=");
      builder.append(tid);
      builder.append(", principal=");
      builder.append(principal);
      builder.append(", endUserIpAddress=");
      builder.append(endUserIpAddress);
      builder.append(", accountId=");
      builder.append(accountId);
      builder.append(", formCreationTime=");
      builder.append(formCreationTime);
      builder.append("]");
      return builder.toString();
    }
  }

  private static byte[] secureResize(byte[] oldBuf, int newSize)
  {
    byte[] newBuf = Arrays.copyOf(oldBuf, newSize);
    Arrays.fill(oldBuf, (byte)0);
    return newBuf;
  }

  /** Reads the first line of the stream (up to first CR or LF chracter).
   * @param is Binary stream to read line of text from.
   * @return Byte buffer containing the first line of text read from the stream, including trailing spaces.
   * <p>The byte data in this buffer will be guaranteed to be the only copy of this data in the entire JVM
   * memory (any other intermediate buffers will be zero-filled before being relegated to garbage collection).</p>
   * <p>If the stream returns EOF immedidately, then a zero-length array will be returned.</p>
   * @throws IOException if an I/O error occurs while reading the line */
  private static byte[] loadRawSecret(InputStream is) throws IOException
  {
    final int ALLOC_STEP_SIZE = 32;
    byte[] secretBuf = new byte[ALLOC_STEP_SIZE];
    int secretLen = 0;

    try
    {
      for (int b = is.read(); b >= 0; b = is.read())
      {
        if (secretLen >= secretBuf.length)
          secretBuf = secureResize(secretBuf, secretBuf.length + ALLOC_STEP_SIZE);
        secretBuf[secretLen++] = (byte)b;
      }
      return (secretLen < secretBuf.length) ? secureResize(secretBuf, secretLen) : secretBuf;
    }
    catch (Throwable e)
    {
      // Need to blank the buffer if an I/O error or OOM occurs (so the secret doesn't appear in the heap dump).
      if (secretBuf != null)
        Arrays.fill(secretBuf, (byte)0);
      throw e;
    }
  }

  /** Loads web form MAC secret from disk.
   * @return SecretKey that can be used to intialise the {@code javax.crypto.Mac} class.
   * @throws InternalServerErrorException if there was an error loading the secret. */
  private static SecretKey getSecret()
  {
    // As an experiment for now, we'll read the secret from disk every time it's requested.
    // This makes it easy to rotate secret keys without having to restart the microservice.
    // However if this strategy is causing performance bottlenecks, then we may need to look at using a file change
    // monitor to notify us if the secret file is modified.  -BLR
    byte[] secretBytes = null;
    try
    {
      secretBytes = loadRawSecret(new FileInputStream(SECRET_FILE));
      return new SecretKeySpec(secretBytes, SECRET_ALGORITHM);
    }
    catch (IOException e)
    {
      throw new InternalServerErrorException("Unable to load web form MAC secret file: " + SECRET_FILE, e);
    }
    finally
    {
      // Need to blank the secret from memory (in case of an I/O error or OOM occurs)
      if (secretBytes != null)
        Arrays.fill(secretBytes, (byte)0);
    }
  }
  
  // This is an experiment to see if it makes it easier for callers
  // that need the key to remember to destroy it when done.
  private static <R> R withSecret(Function<SecretKey, R> action)
  {
    SecretKey secret = getSecret();
    try
    {
      return action.apply(secret);
    }
    finally
    {
      destroySecret(secret);
    }
  }

  private static void withSecret(Consumer<SecretKey> action)
  {
    SecretKey secret = getSecret();
    try
    {
      action.accept(secret);
    }
    finally
    {
      destroySecret(secret);
    }
  }

  private static void destroySecret(SecretKey secret)
  {
    try
    {
      if (secret != null)
        secret.destroy();
    }
    catch (DestroyFailedException e)
    {
      // Unlikely to happen - all we can do is log the exception.
      log.log(Level.FINEST, "Unable to destroy secret", e);
    }
  }

  /** Performs a check to ensure that the webform MAC secret is available and usable.
   * <p>This allows a microservice to perform a start-up self-test to ensure that it can rely on the webform MAC secret
   * being available later on, to catch out any configuration issues at container start-up rather than when the
   * moment comes to actually compute the MAC for an end-user.</p>
   * @throws InternalServerErrorException if there is a configuration error. */
  static void checkSecret()
  {
    final String testMessage = "TotallyLooksLikeAWebFormMacMessage";
    withSecret((secret) -> {
      byte[] testMac = HmacUtil.computeMac(secret, testMessage, MessageSerialisers.UTF8_STRING, MacSerialisers.RAW);
      if (!HmacUtil.verifyMac(secret, testMac, testMessage, MessageSerialisers.UTF8_STRING, MacSerialisers.RAW))
        throw new IllegalArgumentException("Web Form MAC failed to validate test string");
    });
  }

  /** Compute the HMAC for a token-capture web form request.
   * 
   * @param tokeniseRequest Token-capture request parameters
   * @return The HMAC value that proves the web form request was authentic, and timestamp at which the form was issued
   * (used to enforce timeouts on the web form). */
  static HmacTimestamp createCaptureFormHmac(TokeniseRequest tokeniseRequest)
  {
    return withSecret((secret) -> {
      CaptureFormAuthorisation authMsg = new CaptureFormAuthorisation(
        RequestScope.getTid(), RequestScope.getPrincipalId(), tokeniseRequest);
      String hmac = HmacUtil.computeMac(secret, authMsg,
        MessageSerialisers.OBJECT_STREAM, MacSerialisers.BASE64_URL);
      return new HmacTimestamp(hmac,authMsg.formCreationTime);
    });
  }
  
  /** Verifies that a HMAC isued for a token-capture web form is authentic.
   * 
   * @param expectedHmac Pre-computed HMAC that was supplied from the client (that may or may not have been issued
   * by us).
   * @param queryRequest Token-capture completion confirmation request parameters
   * @param formCreationTime Timestamp at which the web form was issued.
   * (when call to {@link #createCaptureFormHmac(TokeniseRequest)} was made).
   * @return {@code true} if {@code expectedHmac} and the actual HMAC computed from {@code queryRequest} and
   * {@code formCreationTime} match; {@code false} if there is a mismatch. */
  static boolean verifyCaptureFormHmac(String expectedHmac, CaptureQueryRequest queryRequest, Instant formCreationTime)
  {
    return withSecret((secret) -> {
      CaptureFormAuthorisation actualAuthMsg = new CaptureFormAuthorisation(
        RequestScope.getTid(), RequestScope.getPrincipalId(), queryRequest, formCreationTime);
      return HmacUtil.verifyMac(secret, expectedHmac, actualAuthMsg,
        MessageSerialisers.OBJECT_STREAM, MacSerialisers.BASE64_URL);
    });
  }
}
