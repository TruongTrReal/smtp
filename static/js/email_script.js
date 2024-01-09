// static/js/email_sript.js 
$(document).ready(function() {
    $('#htmlMessageBox').hide();
    $('#htmlMessage').prop('required', false);

    $('#htmlCheckbox').change(function() {
        if ($(this).is(':checked')) {
            $('#textMessageBox').hide();
            $('#htmlMessageBox').show();
            $('#textMessage').prop('required', false);
            $('#htmlMessage').prop('required', true);
        } else {
            $('#textMessageBox').show();
            $('#htmlMessageBox').hide();
            $('#textMessage').prop('required', true);
            $('#htmlMessage').prop('required', false);
        }
    });

    $('#emailForm').submit(function(e) {
        e.preventDefault();

        var formData = {
            sender: $('#sender').val() + '@truonggpt.com',
            recipients: $('#recipients').val(),
            subject: $('#subject').val(),
            isHtml: $('#htmlCheckbox').is(':checked'),
        };

        // Use htmlMessage if the checkbox is checked, otherwise use message
        formData.message = formData.isHtml ? $('#htmlMessage').val() : $('#textMessage').val();

        // Create FormData object for handling file attachments
        var form = new FormData();
        form.append('attachments', $('#attachments')[0].files[0]);

        // Append other form data to FormData
        Object.keys(formData).forEach(function(key) {
            form.append(key, formData[key]);
        });

        // AJAX request to send email
        $.ajax({
            type: 'POST',
            url: '/email/send',
            data: form,
            contentType: false, // Ensure proper content type for FormData
            processData: false, // Prevent jQuery from processing data
            success: function(response) {
                $('#result').html('<div class="alert alert-success" role="alert">' + response.message + '</div>');
            },
            error: function(error) {
                $('#result').html('<div class="alert alert-danger" role="alert">Error: ' + error.responseJSON.message + '</div>');
            }
        });
    });
});
