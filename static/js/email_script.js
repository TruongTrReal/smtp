// static/js/email_sript.js 
$(document).ready(function() {
    
    $('#sender').val('{{ current_user.username }}');
    $('#sender').css('max-width', '300px');
    $('#htmlMessageBox').hide();
    $('#htmlMessage').prop('required', false);
    $('#recipientsFormatAlert').hide();
    
    $('#sender').on('input', function() {
        var inputValue = $(this).val();

        // Remove spaces
        inputValue = inputValue.replace(/\s+/g, '');

        // Convert to lowercase
        inputValue = inputValue.toLowerCase();

        // Remove non-alphanumeric characters from the beginning of the string
        inputValue = inputValue.replace(/^[^a-z0-9]+/, '');

        // Update the input value
        $(this).val(inputValue.slice(0, 20));  // Limit the length if needed
    });

    var recipientsInput = $('#recipients');
    var sendEmailButton = $('#sendEmailButton');

    recipientsInput.on('input', function() {
        validateAndToggleButton();
    });

    function validateAndToggleButton() {
        var recipientsValue = recipientsInput.val().trim();
        var recipientsArray = recipientsValue.split(',');

        var validEmails = recipientsArray.every(function(email) {
            return isValidEmail(email.trim());
        });
        sendEmailButton.prop('disabled', !validEmails);
        if (!validEmails && recipientsValue !== '') {
            $('#recipientsFormatAlert').show();
        } else {
            $('#recipientsFormatAlert').hide();
        }
    }

    function isValidEmail(email) {
        var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

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
                $('#result').html(response);  // Assuming 'response' contains the HTML content
            },
            error: function(error) {
                $('#result').html(response);
            }
        });
    });
});
