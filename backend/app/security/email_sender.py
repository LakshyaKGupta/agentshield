import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from uuid import UUID

logger = logging.getLogger(__name__)

def send_workspace_invitation(email: str, workspace_name: str, invitation_id: UUID, role: str) -> None:
    """Dispatches a secure HTML workspace invitation. Uses SMTP if configured, otherwise logs to console."""
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_user = os.getenv("SMTP_USERNAME")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    sender_email = os.getenv("SMTP_SENDER", "noreply@agentshield.com")

    # Build the accept link — use FRONTEND_URL env var so it works in production
    frontend_url = os.getenv("FRONTEND_URL", "http://127.0.0.1:5173")
    accept_link = f"{frontend_url}/?accept_invite={invitation_id}"

    subject = f"You have been invited to join {workspace_name} on AgentShield"
    html_content = f"""
    <html>
      <body style="font-family: sans-serif; color: #111; padding: 24px; background: #FAFAF8;">
        <h2 style="font-weight: 300; font-family: serif; font-size: 24px; margin-bottom: 12px;">AgentShield Workspace Invitation</h2>
        <p>You have been invited to join the <strong>{workspace_name}</strong> workspace as an <strong>{role}</strong>.</p>
        <p style="margin-top: 24px; margin-bottom: 24px;">
          <a href="{accept_link}" style="background: #111; color: #fff; padding: 12px 24px; border-radius: 99px; text-decoration: none; font-weight: 600; font-size: 14px;">Accept Invitation</a>
        </p>
        <p style="color: #666; font-size: 12px; margin-top: 36px;">If you did not expect this invitation, you can safely ignore this email.</p>
      </body>
    </html>
    """

    if smtp_host and smtp_port:
        try:
            logger.info(f"Connecting to SMTP host {smtp_host}:{smtp_port} to email {email}...")
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = email
            
            part = MIMEText(html_content, "html")
            msg.attach(part)
            
            # Connect to SMTP
            with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10.0) as server:
                server.ehlo()
                if os.getenv("SMTP_USE_TLS", "true").lower() in {"true", "1", "yes"}:
                    server.starttls()
                    server.ehlo()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(sender_email, email, msg.as_string())
                
            logger.info(f"Successfully sent invitation email to {email}")
        except Exception as e:
            logger.error(f"Failed to dispatch SMTP invitation email to {email}: {e}", exc_info=True)
    else:
        # Fallback: Print premium formatted terminal block for simple local evaluation!
        logger.info("\n" + "="*80 + "\n" +
                    f"LOCAL DEV / SANDBOX MODE: INVITATION DISPATCHED SIMULATION\n" +
                    f"Recipient: {email}\n" +
                    f"Role: {role}\n" +
                    f"Workspace: {workspace_name}\n" +
                    f"Action Required: Click accept in the settings UI directory, or open the link below in your browser:\n" +
                    f"Accept URL -> {accept_link}\n" +
                    "="*80 + "\n")
