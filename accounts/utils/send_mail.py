from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.conf import settings

def send_html_email(subject, template_name, context, to_email):
    # Render the template with context data
    html_message = render_to_string(template_name, context)
    
    # Send email
    email = EmailMessage(subject, html_message, settings.DEFAULT_FROM_EMAIL, [to_email])
    email.content_subtype = 'html'  # Important to set the content type to HTML
    email.send()
    

