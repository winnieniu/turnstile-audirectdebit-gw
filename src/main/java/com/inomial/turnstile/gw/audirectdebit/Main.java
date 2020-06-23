package com.inomial.turnstile.gw.audirectdebit;

import com.google.common.collect.Sets;
import com.inomial.secore.http.HttpServer;
import com.inomial.secore.kafka.MessageProducer;

import java.util.Set;

public class Main
{
  public static void main(String[] argv)
  {
    System.out.println("Australia Direct Debit Turnstile gateway is starting up.");

    // Load form HMAC secrets now so any configuration errors will appear in startup log messages,
    // rather than upon first transaction.
    System.out.println("Checking if web form MAC secret is available.");
    WebFormMac.checkSecret();
    System.out.println("Web Form MAC secret is OK.");

    // Start message producer
    System.out.println("Starting Kafka MessageProducer.");
    MessageProducer.start("turnstile-audirectdebit-gw");
    System.out.println("MessageProducer started.");

    HttpServer.addResourceClass(RSAUDirectDebit.class);
    Set<String> roles = Sets.newHashSet(
            "authenticated", // smile
            "turnstile", // apps
            "enduser"); // portal
    Set<String> realms = Sets.newHashSet("smile", "soap", "portal", "apps");
    HttpServer.start(realms, roles);
    System.out.println("HTTP server started.");
  }
}
