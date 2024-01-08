var idp = (function() {
    //*** <CHANGE THESE VARIABLES> ***//
    // IDP - Auth0 Domain
    var idp = 'https://codeflowtesting.eu.auth0.com';
    // Client ID from Auth0
    var clientId = 'fW9ijlTpUUrYsg6L6PNjC5VQAnss9rdv';
    // ID of user you setup in Auth0
    var user_id = 'auth0|64ad30366a1c99d41895941b';
    //*** </CHANGE THESE VARIABLES> ***//

    // Host has to be https
    var host = location.origin;
    // Generated Auth URL using the idp and client ID
    var authUrl = idp + '/authorize/?client_id=' + clientId;
    // Redirect urls used when calling the idp
    var redirect_uri = 'https://jlawthom.github.io/lp-iframe-auth-redirect/';
    var logRedirect_uri = 'https://jlawthom.github.io/lp-code-flow-auth-page/';
    // Authentication endpoint
    var authenticationEndPoint = authUrl + '&response_type=code&redirect_uri={REDIRECTURI}&state=OPAQUE_VALUE&connection=Username-Password-Authentication&scope=openid';
    // logout endpoint
    var logoutEndpoint = idp + '/v2/logout?returnTo={REDIRECTURI}';

    // Encoded uris for authentication, logging in and out
    var encoded = encodeURI(authenticationEndPoint.replace('{REDIRECTURI}', redirect_uri));
    var loginEncoded = encodeURI(authenticationEndPoint.replace('{REDIRECTURI}', logRedirect_uri));
    var logoutEncoded = encodeURI(logoutEndpoint.replace('{REDIRECTURI}', logRedirect_uri));

    // Allowed Origins to recieve the postmessage from the iFrames
    var allowedOrigins = [
        location.origin
    ];

    // Var to store the listener function so we can remove the listener
    var listenerFunc;

    // Function to set cookie
    function setCookie() {
        var d = new Date();
        // 36000 is the value set in Auth0 configuration
        d.setTime(d.getTime() + (36000 * 1000));
        var expires = "expires="+d.toUTCString();
        document.cookie = "authenticated=true;" + expires + ";path=/";
    }

    function deleteCookie() {
        document.cookie = "authenticated=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    }

    // Function to get cookie by name
    function getCookie() {
        var name = "authenticated=";
        var ca = document.cookie.split(';');
        for(var i = 0; i < ca.length; i++) {
            var c = ca[i];
            while (c.charAt(0) == ' ') {
                c = c.substring(1);
            }
                if (c.indexOf(name) == 0) {
                return c.substring(name.length, c.length);
            }
        }
        return '';
    }

    // Function to add an event listener to an element
    var bindEvent = function(element, eventName, eventHandler) {
        if (element.addEventListener) {
            element.addEventListener(eventName, eventHandler, false);
        }
    };

    // Function to remove an event listener from an element
    var unBindEvent = function(element, eventName, eventHandler) {
        if (element.removeEventListener) {
            element.removeEventListener(eventName, eventHandler);
        }
    };

    // For IE
    function isInArray(value, array) {
        return array.indexOf(value) > -1;
    }

    // Function to build the iFrame which will redirect to the IDP and return the token to the main window
    var buildiFrame = function(url) {
        var iframe = document.createElement('iframe');

        // Assign the iFrame an id and make it hidden
        iframe.setAttribute('id', 'iframe');
        iframe.setAttribute("hidden", true);
        // Place the iFrame at the end of the document
        document.body.appendChild(iframe);
        console.log('9. iFrame dynamically inserted');

        // Navigate the iFrame to the authentication end point
        iframe.setAttribute('src', url);
        console.log('10. iFrame redirected to authentication endpoint');
    }

    // Function that gets called when the iFrame passes an authentication code to the main page
    var eventHandler = function(e, lpCallback) {
        var iframe = document.getElementById("iframe");
        var authCode;
        // Check that the message is sent from the iFrame
        if (isInArray(e.origin, allowedOrigins)) {
            authCode = e.data;

            if (iframe) {
                // Remove the iFrame from the page
                document.body.removeChild(iframe);
                console.log('14. iFrame removed')
            }

            // Call the callback from lpGetAuthenticationCode to pass the auth code to LiveEngage
            lpCallback({ssoKey: authCode, redirect_uri: redirect_uri});
            console.log('15. Listener for PostMessage passed authCode in callback')

            // Unbind the message event
            unBindEvent(window, 'message', listenerFunc);
        }
    }

    // Function that will be called by LiveEngage when the engagement is clicked
    window.lpGetAuthenticationCode = function(callback) {
        if (isLoggedIn()) {
            console.log('7. Trigger function run');

            listenerFunc = function(e) { eventHandler(e, callback) };

            // Listen for the authentication token from the iFrame
            bindEvent(window, 'message', listenerFunc);
            console.log('8. Subscribed to PostMessage');

            // Build the iFrame
            buildiFrame(encoded);
        }
        else {
            // Not logged in - pass null
            callback(null);
        }
    };

    // On pageload
    document.addEventListener('DOMContentLoaded', function(){
        console.log('1. Main Frame loaded');

        // Get login and logout button ids
        var loginButton = document.getElementById('loginButton');
        var logoutButton = document.getElementById('logoutButton');

        // Set login and logout button urls
        loginButton.setAttribute('href', loginEncoded);
        logoutButton.setAttribute('href', logoutEncoded);

        // If a login cookie exists, hide the login button and add the authenticated section
        // Otherwise hide the logout button as we need to login first
        if (!isLoggedIn()) {
            logoutButton.style.display = 'none';
            loginButton.style.display = 'inline-block';
        } else {
            console.log('2. Identity function registered');
            loginButton.style.display = 'none';
            logoutButton.style.display = 'inline-block';
        }

        bindEvent(loginButton, 'click', setCookie);
        bindEvent(logoutButton, 'click', deleteCookie);

        var event = document.createEvent("Event");
        event.initEvent("IdpReady", true, true);
        document.dispatchEvent(event);
    });

    function isLoggedIn() {
       return (getCookie() !== '');
    }

    return {
        loggedIn: isLoggedIn,
        user_id: user_id
    }
})();

document.addEventListener("IdpReady", function() {

    // Function that should be registered with LivePerson using lpTag.identities.push() when consumer is logged in
    // in order to identify the consumer
    var identityFn = function(callback) {
        var identity = {
            iss: "issuertesting1.com", // should match the "iss" value in the JWT
            acr: "loa1",
            sub: idp.user_id // should match the "sub" value in the JWT
        }
        callback(identity);
        console.log('4. Consumer identity passed', identity);
    }

    if (idp.loggedIn()) {
        lpTag.section = ['auth:authenticated'];
        lpTag.identities = lpTag.identities || [];
        lpTag.identities.push(identityFn);
    }
    else {
        lpTag.section = ['auth:unauthenticated'];
    }
});
