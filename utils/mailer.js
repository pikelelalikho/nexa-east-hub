import 'dotenv/config';
import nodemailer from 'nodemailer';

const emailEnabled = Boolean(process.env.EMAIL_USER && process.env.EMAIL_PASS);
const emailFrom = `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM_EMAIL}>`;

function getEmailTransportConfig() {
  const auth = {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  };

  if (process.env.EMAIL_HOST) {
    const port = Number(process.env.EMAIL_PORT) || 587;
    return {
      host: process.env.EMAIL_HOST,
      port,
      secure: process.env.EMAIL_SECURE === 'true' || port === 465,
      auth
    };
  }

  return {
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth
  };
}

export const transporter = emailEnabled
  ? nodemailer.createTransport(getEmailTransportConfig())
  : null;

export async function sendMail(mailOptions) {
  if (!transporter) {
    console.warn(`Email skipped because SMTP is not configured: ${mailOptions.subject}`);
    return false;
  }

  await transporter.sendMail({
    ...mailOptions,
    from: emailFrom
  });
  return true;
}
