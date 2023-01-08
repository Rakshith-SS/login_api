import smtplib
import os


smtp_server = "smtp.gmail.com"
port = 465
sender_email = os.environ.get("MAIL")
password = os.environ.get("PASSPHRASE")


def send_otp(reciever_email, random_number):
    """ Sends otp, to a given email
        address
    """
    subject = "Login OTP"
    message = f"Your OTP is {random_number}"

    msg = f"Subject: {subject}\n\n{message}"
    with smtplib.SMTP_SSL(smtp_server, port) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, reciever_email, msg)
