/*
 * Copyright 2025 olden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ukrcom.routefilterupdater;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.*;
import javax.mail.internet.*;
import java.util.Properties;

/** Sends a plain-text email report via SMTP. */
public class EmailReporter {

    private static final Logger log = LoggerFactory.getLogger(EmailReporter.class);

    private final Config config;

    public EmailReporter(Config config) {
        this.config = config;
    }

    public void send(String subject, String body) throws MessagingException {
        if (config.smtpHost.isBlank() || config.reportTo.isBlank() || config.reportFrom.isBlank()) {
            log.warn("SMTP not fully configured (SMTP_HOST / REPORT_TO / REPORT_FROM), skipping report");
            return;
        }

        Properties props = new Properties();
        props.put("mail.smtp.host", config.smtpHost);
        props.put("mail.smtp.port", String.valueOf(config.smtpPort));
        props.put("mail.smtp.auth", String.valueOf(!config.smtpUser.isBlank()));

        boolean local = "127.0.0.1".equals(config.smtpHost) || "localhost".equals(config.smtpHost);
        props.put("mail.smtp.starttls.enable", String.valueOf(!local));
        if (!local) {
            props.put("mail.smtp.ssl.trust", "*");
        }

        Session session;
        if (!config.smtpUser.isBlank()) {
            session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(config.smtpUser, config.smtpPass);
                }
            });
        } else {
            session = Session.getInstance(props);
        }

        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(config.reportFrom));
        msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(config.reportTo));
        msg.setSubject(subject);
        msg.setText(body, "UTF-8");

        Transport.send(msg);
        log.info("Report sent → {}", config.reportTo);
    }
}
