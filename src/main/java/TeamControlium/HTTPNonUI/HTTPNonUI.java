package TeamControlium.HTTPNonUI;

import TeamControlium.Utilities.*;

import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.*;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;

import static TeamControlium.HTTPNonUI.HTTPNonUI.RequestTypes.BadProtocol;
import static TeamControlium.HTTPNonUI.HTTPNonUI.RequestTypes.BadlyFormedHeaderLine;
import static TeamControlium.HTTPNonUI.HTTPNonUI.RequestTypes.InvalidHTTPVersion;

public class HTTPNonUI {
    public enum RequestTypes {
        /// <summary>
        /// (Default) HTTP interaction is normal and should work at the HTTP level.
        /// </summary>
        Normal,
        /// <summary>
        /// Requested HTTP Method is overridden with text INVALID.
        /// </summary>
        InvalidHTTPMethod,
        /// <summary>
        /// An HTTP version of 0.0 is used (usually this would be 1.1)
        /// </summary>
        InvalidHTTPVersion,
        /// <summary>
        /// The protocol is PHHT rather than HTTP
        /// </summary>
        BadProtocol,
        /// <summary>
        /// Instead of request header lines being Key: Value, they are Key; Value (IE. a Semicolon is used instead)
        /// </summary>
        BadlyFormedHeaderLine,
        /// <summary>
        /// Instead of CarriageReturn Linefeed, Linefeed CarriageReturn used in header lines seperators.
        /// </summary>
        HeaderLinesLFBeforeCR,
        /// <summary>
        /// Instead of CarriageReturn Linefeed, Linefeed characters only used in header lines seperators.
        /// </summary>
        HeaderLinesLFOnly,
        /// <summary>
        /// Instead of CarriageReturn Linefeed, CarriageReturn characters only used in header lines seperators.
        /// </summary>
        HeaderLinesCROnly,
        /// <summary>
        /// Fail the SSL Server certificate validation
        /// </summary>
        DoNotAcceptServerCertificate
    }
    public enum HTTPMethodTypes {Post, Put, Get, Delete}


    private RequestTypes _requestType;
    private boolean useSSL;

    public RequestTypes getRequestType() {
        return _requestType;
    }

    public RequestTypes setRequestType(RequestTypes requestType) {
        _requestType = requestType;
        return _requestType;
    }

    private String _requestHeader;

    public String getRequestHeader() {
        return _requestHeader;
    }

    public String setRequestHeader(String requestHeader) {
        _requestHeader = requestHeader;
        return _requestHeader;
    }

    private String _requestBody;

    public String getRequestBody() {
        return _requestBody;
    }

    public String setRequestBody(String requestBody) {
        _requestHeader = requestBody;
        return _requestHeader;
    }

    private String _responseRaw;

    public String getResponseRaw() {
        return _responseRaw;
    }

    public String setResponseRaw(String responseRaw) {
        _responseRaw = responseRaw;
        return _responseRaw;
    }

    private String _sslProtocol;

    public String getSSLProtocol() {
        return _sslProtocol;
    }

    public String setSSLProtocol(String sslProtocol) {
        _sslProtocol = sslProtocol;
        return _sslProtocol;
    }

    private Duration _timeout;

    public Duration getTimeout() {
        return _timeout;
    }

    public Duration setTimeout(Duration timeout) {
        _timeout = timeout;
        return _timeout;
    }

    private X509Certificate _clientCertificate;

    public X509Certificate getClientCertificate() {
        return _clientCertificate;
    }

    public X509Certificate setClientCertificate(X509Certificate clientCertificate) {
        _clientCertificate = clientCertificate;
        return clientCertificate;
    }

    private Boolean _logTransactions;

    public Boolean getLogTransactions() {
        return _logTransactions;
    }

    public Boolean setLogTransactions(Boolean logTransactions) {
        _logTransactions = logTransactions;
        return logTransactions;
    }


    /// <summary>
    /// Delegate to do custom certificate validation
    /// </summary>
    private static BiConsumer<X509Certificate[], String> _CertificateValidator = null;

    public static void setCertificateValidator(BiConsumer<X509Certificate[], String> certificateValidator) {
        _CertificateValidator = certificateValidator;
    }

    public HTTPNonUI() {
        /// <summary>
        /// Instantiates an instance of the HTTPNonUI class, used for testing an HTTP interface when used for Non-UI interaction (IE. WebServices, Json etc...)
        /// </summary>
        setRequestType(RequestTypes.Normal);
        setRequestHeader("");
        setTimeout(Duration.ofMillis(10000));  // Default 10 second timeout
        setClientCertificate(null);
        setSSLProtocol("None");
        setCertificateValidator(null);
        String logTransactionsString;
        try {
            logTransactionsString = TestData.getItem(String.class, "HTTPNonUI", "LogTransactions");
        } catch (Exception e) {
            logTransactionsString = "No";
        }
        setLogTransactions(General.IsValueTrue(logTransactionsString));
    }

    /// <summary>
    /// Encodes a plain text string into Base64.
    /// </summary>
    /// <param name="plainText">Text to be converted</param>
    /// <returns>Equivalent string Base64 encoded</returns>
    public static String base64Encode(String plainText) {
        return Base64.getEncoder().encodeToString(plainText.getBytes());
    }


    public String buildRequestHeader(HTTPMethodTypes httpMethod, String resourcePath, Map<String, String> requestHeaders, Map<String, String> parameters) throws Exception {
        List<String> returnHeader = new ArrayList<String>();
        String returnString = null;
        //
        // Do the first line first....
        //
        // Top line looks something like this:-
        // GET /path/to/resource/page.html?param1=hello&param2=another HTTP/1.0
        //

        // HTTP Method
        String topLine = null;
        if (getRequestType() == RequestTypes.InvalidHTTPMethod)
            topLine = "INVALID ";
        else
            switch (httpMethod) {
                case Post:
                    topLine = "POST";
                    break;
                case Put:
                    topLine = "PUT";
                    break;
                case Get:
                    topLine = "GET";
                    break;
                case Delete:
                    topLine = "DELETE";
                    break;
                default:
                    throw new Exception("httpMethod " + httpMethod.name() + " unsupported");
            }
        // ResourcePath - Is the path that defines the resource being accessed
        topLine += " " + resourcePath;

        // If Parameters have been passed in use them (Irrelevant of Method - test may be doing this deliberately to force an error etc...)
        if (parameters!=null && parameters.size() > 0) {
            char joiner = '?';
            for (Map.Entry<String, String> parameter : parameters.entrySet()) {
                topLine += joiner + parameter.getKey() + "=" + parameter.getValue();
                joiner = '&';
            }
        }
        topLine += " ";

        // HTTP Version - This is always HTTP/1.1.  However, test may want to use bad protocol and/or version
        topLine += (getRequestType() == BadProtocol) ? "PHHT/" : "HTTP/";
        topLine += (getRequestType() == InvalidHTTPVersion) ? "0.0" : "1.1";
        // Add top line to list of header lines
        returnHeader.add(topLine);

        //
        // And the rest of the header lines.  These are in the format of:-
        // Key:Value although the test may want badly formed lines where we use ; instead of :
        //
        if (requestHeaders != null && requestHeaders.size() > 0) {
            String joiner = (getRequestType() == BadlyFormedHeaderLine) ? "; " : ": ";
            for (Map.Entry<String, String> requestHeader : requestHeaders.entrySet()) {
                returnHeader.add(requestHeader.getKey() + joiner + requestHeader.getValue());
            }
        }

        //
        // Finally, build the actual Header as a single string delimted with CR-LFs...  Test may want to use
        // different line endings, so allow for that....
        //
        String headerLinesSeperator = "\r\n";
        switch (getRequestType()) {
            case HeaderLinesCROnly:
                headerLinesSeperator = "\r";
                break;
            case HeaderLinesLFOnly:
                headerLinesSeperator = "\n";
                break;
            case HeaderLinesLFBeforeCR:
                headerLinesSeperator = "\n\r";
                break;
        }
        for (String currentLine : returnHeader) returnString += currentLine + headerLinesSeperator;

        setRequestHeader(returnString);

        return returnString;
    }

    /// <summary>
    /// Builds and returns an HTTP Request header.  Header is well-formed unless  RequestType is set to RequestTypes.InvalidHTTPMethod, RequestTypes.BadProtocol, RequestTypes.InvalidHTTPVersion or RequestTypes.BadlyFormedHeaderLine.
    /// </summary>
    /// <param name="HTTPMethod">HTTP Method to be used.  GET or POST are currentlt supported.  Overridden if RequestType is set to RequestTypes.InvalidHTTPMethod</param>
    /// <param name="ResourcePath">Path to resource on the server</param>
    /// <param name="RequestHeaders">Request header lines to be added</param>
    /// <returns>HTTP Header to be used in request</returns>
    public String buildRequestHeader(HTTPMethodTypes httpMethod, String resourcePath, Map<String, String> requestHeaders) throws Exception {
        // No parameters being used
        return buildRequestHeader(httpMethod, resourcePath, requestHeaders, null);
    }

    /// <summary>
    /// Builds and returns an HTTP Request header.  Header is well-formed unless  RequestType is set to RequestTypes.InvalidHTTPMethod, RequestTypes.BadProtocol, RequestTypes.InvalidHTTPVersion or RequestTypes.BadlyFormedHeaderLine.
    /// </summary>
    /// <param name="HTTPMethod">HTTP Method to be used.  GET or POST are currentlt supported.  Overridden if RequestType is set to RequestTypes.InvalidHTTPMethod</param>
    /// <param name="ResourcePath">Resource Path for use in HTTP Header top-line</param>
    /// <returns>HTTP Header to be used in request</returns>
    public String buildRequestHeader(HTTPMethodTypes httpMethod, String resourcePath) throws Exception {
        // No request header lines or parameters
        return buildRequestHeader(httpMethod, resourcePath, null,null);
    }

    /// <summary>
    /// Sends a Web Request using the RequestHeader and RequestBody properties
    /// returning a Key/Value pair collection of the raw response.
    /// </summary>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendWebRequest(String url, int port)  throws Exception {
        String response = sendTCPRequest(url, port, buildRequest(null, null));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader properties and passed RequestBody, sends the request data using plain text to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>If passed RequestBody is empty or null, RequestBody property is used.</remarks>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendWebRequest(String url, int port, String requestBody) throws Exception {
        String response = sendTCPRequest(url, port, buildRequest(null, requestBody));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the passed RequestHeader and RequestBody, sends the request data using plain text to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>If passed RequestBody and/or RequestHeader are empty or null, RequestBody &amp; RequestHeader properties are used.</remarks>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestHeader">Header of HTTP Request to be sent</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendWebRequest(String url, int port, String requestHeader, String requestBody) throws Exception
    {
        String response = sendTCPRequest(url, port, buildRequest(requestHeader, requestBody));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the passed RequestHeader and RequestBody, sends the request data using plain text to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>
    /// <para>If passed RequestBody and/or RequestHeader are empty or null, RequestBody &amp; RequestHeader properties are used.</para>
    /// <para>If response data is not fully received within ReceiveTimeout an Exception is thrown.</para>
    /// </remarks>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestHeader">Header of HTTP Request to be sent</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <param name="ReceiveTimeout">Maximum time allowed for response data to be fully received.</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendWebRequest(String url, int port, String requestHeader, String requestBody, Duration timeout) throws Exception {
        String response = sendTCPRequest(url, port, buildRequest(requestHeader, requestBody), timeout);
        return decodeResponse(response);
    }


    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>No certificate is used in Request</remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, String url, int port) throws Exception
    {
        String response = sendTCPRequest(sslProtocol, url, port, buildRequest(null, null));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="CertificateFile">Certificate to use in transaction</param>
    /// <param name="CertificatePassword">Password for Certificate authentication.</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, String certificateFile, String certificatePassword, String url, int port) throws Exception
    {
        String response = sendTCPRequest(sslProtocol, certificateFile, certificatePassword, url, port, buildRequest(null, null));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="ClientCertificate">X509 Certificate to use in transaction</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, X509Certificate clientCertificate, String url, int port) throws Exception
    {
        String response = sendTCPRequest(sslProtocol, clientCertificate, url, port, buildRequest(null, null));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>If passed RequestBody is empty or null, RequestBody property is used.</remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="CertificateFile">Certificate to use in transaction</param>
    /// <param name="CertificatePassword">Password for Certificate authentication.</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, String certificateFile, String certificatePassword, String url, int port, String requestBody)  throws Exception  {
        String response = sendTCPRequest(sslProtocol, certificateFile, certificatePassword, url, port, buildRequest(null, requestBody));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>If passed RequestBody is empty or null, RequestBody property is used.</remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="ClientCertificate">X509 Certificate to use in transaction</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, X509Certificate clientCertificate, String url, int port, String requestBody) throws Exception {
        String response = sendTCPRequest(sslProtocol, clientCertificate, url, port, buildRequest(null, requestBody));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>If passed RequestBody and/or RequestHeader are empty or null, RequestBody &amp; RequestHeader properties are used.</remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="CertificateFile">Certificate to use in transaction</param>
    /// <param name="CertificatePassword">Password for Certificate authentication.</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestHeader">Header of HTTP Request to be sent</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, String certificateFile, String certificatePassword, String url, int port, String requestHeader, String requestBody) throws Exception{
        String response = sendTCPRequest(sslProtocol, certificateFile, certificatePassword, url, port, buildRequest(requestHeader, requestBody));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>If passed RequestBody and/or RequestHeader are empty or null, RequestBody &amp; RequestHeader properties are used.</remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="ClientCertificate">X509 Certificate to use in transaction</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestHeader">Header of HTTP Request to be sent</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, X509Certificate clientCertificate, String url, int port, String requestHeader, String requestBody) throws Exception {
        String response = sendTCPRequest(sslProtocol, clientCertificate, url, port, buildRequest(requestHeader, requestBody));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>
    /// <para>If passed RequestBody and/or RequestHeader are empty or null, RequestBody &amp; RequestHeader properties are used.</para>
    /// <para>If response data is not fully received within ReceiveTimeout an Exception is thrown.</para>
    /// </remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="CertificateFile">Certificate to use in transaction</param>
    /// <param name="CertificatePassword">Password for Certificate authentication.</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestHeader">Header of HTTP Request to be sent</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <param name="ReceiveTimeout">Maximum time allowed for response data to be fully received.</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, String certificateFile, String certificatePassword, String url, int port, String requestHeader, String RequestBody, Duration receiveTimeout) throws Exception {
        String response = sendTCPRequest(sslProtocol, certificateFile, certificatePassword, url, port, buildRequest(requestHeader, RequestBody), receiveTimeout);
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>
    /// <para>If passed RequestBody and/or RequestHeader are empty or null, RequestBody &amp; RequestHeader properties are used.</para>
    /// <para>If response data is not fully received within ReceiveTimeout an Exception is thrown.</para>
    /// </remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="ClientCertificate">X509 Certificate to use in transaction</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestHeader">Header of HTTP Request to be sent</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <param name="ReceiveTimeout">Maximum time allowed for response data to be fully received.</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, X509Certificate clientCertificate, String url, int port, String requestHeader, String requestBody, Duration receiveTimeout)  throws Exception {
        String response = sendTCPRequest(sslProtocol, clientCertificate, url, port, buildRequest(requestHeader, requestBody), receiveTimeout);
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>
    /// <para>If passed RequestBody and/or RequestHeader are empty or null, RequestBody &amp; RequestHeader properties are used.</para>
    /// <para>If request data is not fully sent within SendTimeout an Exception is thrown.</para>
    /// <para>If response data is not fully received within ReceiveTimeout an Exception is thrown.</para>
    /// </remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="CertificateFile">Certificate to use in transaction</param>
    /// <param name="CertificatePassword">Password for Certificate authentication.</param>
    /// <param name="CertificateValidationCallback">Certificate Validation Callback if internal callback not used. Internal callback always accepts server certificate unless RequestTypes.DoNotAcceptServerCertificate is active.</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestHeader">Header of HTTP Request to be sent</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <param name="SendTimeout">Maximum time allowed for request data to be fully sent.</param>
    /// <param name="ReceiveTimeout">Maximum time allowed for response data to be fully received.</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, String certificateFile, String certificatePassword, BiConsumer<X509Certificate[], String> certificateValidationCallback, String url, int port, String requestHeader, String requestBody, Duration timeout) throws Exception {
        setCertificateValidator(certificateValidationCallback);
        String response = sendTCPRequest(sslProtocol, certificateFile, certificatePassword, url, port, buildRequest(requestHeader, requestBody), timeout);
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>
    /// <para>If passed RequestBody and/or RequestHeader are empty or null, RequestBody &amp; RequestHeader properties are used.</para>
    /// <para>If request data is not fully sent within SendTimeout an Exception is thrown.</para>
    /// <para>If response data is not fully received within ReceiveTimeout an Exception is thrown.</para>
    /// <para>Default send and receive timeouts are used</para>
    /// </remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="ClientCertificate">X509 Certificate to use in transaction</param>
    /// <param name="CertificateValidationCallback">Certificate Validation Callback if internal callback not used. Internal callback always accepts server certificate unless RequestTypes.DoNotAcceptServerCertificate is active.</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestHeader">Header of HTTP Request to be sent</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, X509Certificate clientCertificate, BiConsumer<X509Certificate[], String> certificateValidationCallback, String url, int port, String requestHeader, String requestBody) throws Exception {
        setCertificateValidator(certificateValidationCallback);
        String response = sendTCPRequest(sslProtocol, clientCertificate, url, port, buildRequest(requestHeader, requestBody));
        return decodeResponse(response);
    }

    /// <summary>
    /// Builds an HTTP request using the RequestHeader and RequestBody properties, sends the request data using secure sockets to the defined socket (URL:Port), receives and decodes the response,
    /// returning a Key/Value pair collection of the response.
    /// </summary>
    /// <remarks>
    /// <para>If passed RequestBody and/or RequestHeader are empty or null, RequestBody &amp; RequestHeader properties are used.</para>
    /// <para>If request data is not fully sent within SendTimeout an Exception is thrown.</para>
    /// <para>If response data is not fully received within ReceiveTimeout an Exception is thrown.</para>
    /// </remarks>
    /// <param name="SSLProtocol">SSL/TSL Protocols to be allowed in request</param>
    /// <param name="ClientCertificate">X509 Certificate to use in transaction</param>
    /// <param name="CertificateValidationCallback">Certificate Validation Callback if internal callback not used. Internal callback always accepts server certificate unless RequestTypes.DoNotAcceptServerCertificate is active.</param>
    /// <param name="url">URL (IP Address) to send the request to.</param>
    /// <param name="Port">Port to send request to</param>
    /// <param name="RequestHeader">Header of HTTP Request to be sent</param>
    /// <param name="RequestBody">Body of HTTP request to be sent</param>
    /// <param name="SendTimeout">Maximum time allowed for request data to be fully sent.</param>
    /// <param name="ReceiveTimeout">Maximum time allowed for response data to be fully received.</param>
    /// <returns>Decodes response from HTTP request.</returns>
    public Map<String, String> sendSSLWebRequest(String sslProtocol, X509Certificate clientCertificate, BiConsumer<X509Certificate[], String> certificateValidationCallback, String url, int port, String requestHeader, String requestBody, Duration timeout) throws Exception  {
        setCertificateValidator(certificateValidationCallback);
        String response = sendTCPRequest(sslProtocol, clientCertificate, url, port, buildRequest(requestHeader, requestBody), timeout);
        return decodeResponse(response);
    }


    private String doTCPRequest(String url, int port,String request) throws Exception {
        char[] buf = new char[1024];
        String response="";
        Socket tcpClient;
        PrintWriter outputStream=null;
        BufferedReader inputStream=null;

        if (url==null) throw new Exception("Paramter url cannot be null");
        if (request==null) throw new Exception("Paramter request cannot be null");

        if (getLogTransactions()) {
            try {
                String logFileName = Paths.get(System.getProperty("user.dir"), "request_" + URLEncoder.encode(url, "UTF-8") + "_" + (new SimpleDateFormat("yy-MM-dd_HH-mm-ss-ff")).format(Calendar.getInstance().getTime()) + ".txt").toString();
                Logger.WriteTextToFile(logFileName, true, url + ":" + port + "\r\n" + request);
                Logger.WriteLine(Logger.LogLevels.TestInformation, String.format("Send to [%s] logged in [%s]", url, logFileName));
            }
            catch (Exception e) {
                Logger.WriteLine(Logger.LogLevels.Error, String.format("Unable to write to HTTPNonUI logging file: %s", e.toString()));
            }

        }

        try {
            int timeoutMillis = (int)getTimeout().toMillis();
            tcpClient = new Socket(url,port);
            tcpClient.setSoTimeout(timeoutMillis);
            outputStream = new PrintWriter(tcpClient.getOutputStream(),true);
            inputStream = new BufferedReader(new InputStreamReader(tcpClient.getInputStream()));
        }
        catch (Exception e) {
            throw new Exception("Error creating streams",e);
        }

        try {
            outputStream.print(request);
            outputStream.flush();
            String block;
            int size = 0;
            while ((size = inputStream.read(buf)) != -1) {
                response += new String(buf,0,size);
            }
        }
        catch (Exception e) {
            throw new Exception("Error communicating",e);
        }

        return response;
    }


    private String sendTCPRequest(String url, int port, String request)throws Exception {
        return doTCPRequest(url, port, request);
    }

    private String sendTCPRequest(String url, int port, String request, Duration timeout) throws Exception {
        setTimeout(timeout);
        return doTCPRequest(url, port, request);
    }

    private String sendTCPRequest(String sslProtocol, String certificateFile, String certificatePassword, String url, int port, String request)
    {
        // Need to do
 //       this.sslProtocol = SSLProtocol;
 //       ClientCertificate = new X509Certificate2(CertificateFile, CertificatePassword);
 //       return DoTCPRequest(URL, Port, request);
        return null;
    }

    private String sendTCPRequest(String SSLProtocol, X509Certificate clientCertificate, String url, int port, String request)
    {
//        useSSL = true;
//        this.sslProtocol = SSLProtocol;
//        this.ClientCertificate = ClientCertificate;=q~    `   `        return DoTCPRequest(URL, Port, request);
        return null;
    }

    private String sendTCPRequest(String SSLProtocol, String url, int port, String request)
    {
//        useSSL = true;
//        this.sslProtocol = SSLProtocol;
//        this.ClientCertificate = null;
//        return DoTCPRequest(URL, Port, request);
        return null;
    }

    private String sendTCPRequest(String sslProtocol, String certificateFile, String certificatePassword, String url, int port, String request, Duration timeout)
    {
 //       useSSL = true;
 //       this.sslProtocol = SSLProtocol;
 //       ClientCertificate = new X509Certificate2(CertificateFile, CertificatePassword);
 //       receiveTimeout = ReceiveTimeout;
 //       return DoTCPRequest(URL, Port, request);
        return null;
    }

    private String sendTCPRequest(String sslProtocol, X509Certificate ClientCertificate, String url, int Port, String request, Duration timeout)
    {
 //       useSSL = true;
 //       this.sslProtocol = SSLProtocol;
 //       this.ClientCertificate = ClientCertificate;
 //       receiveTimeout = ReceiveTimeout;
 //       return DoTCPRequest(URL, Port, request);
        return null;
    }

    private String buildRequest(String requestHeader, String requestBody)
    {
        // Stitch the HTTP Request Body to the HTTP Request Header.  HTTP requires a double CRLF between the header and the body
        //
        //
        // If the Header we have been passed is empty, use the class RequestHeader property (which itself may be empty...)  This way, a user may build the HTTP Header
        // themselves...
        String request = (requestHeader==null || requestHeader=="") ? getRequestHeader() : requestHeader;
        if (request==null || request=="")
            // If the request has no header, we can just use the passed Request Body.
            request = (requestBody==null ? "" : requestBody);
        else
        {
            // If we do have an HTTP header, ensure there is a double CRLF before the Body (if any...)
            if (!request.endsWith("\n") & !request.endsWith("\r")) request += "\r\n";
            request += "\r\n" + (requestBody==null || requestBody=="" ? getRequestBody() : requestBody);
        }
        return request;
    }

    private Map<String, String> decodeResponse(String rawData) throws Exception {
        Map<String, String> returnData = new HashMap<String, String>();
        setResponseRaw(rawData);
        try {
            //
            // Do First line (IE. HTTP/1.1 200 OK)
            //
            if (rawData==null || rawData=="") {
                returnData.put("HTTPVersion", "Unknown - Empty Response");
                returnData.put("StatusCode", "Unknown - Empty Response");
                return returnData;

            }

            // We have something.....  Is it HTTP?
            if (!rawData.startsWith("HTTP")) {
                String firstLine = rawData.split("\r")[0];
                firstLine = (firstLine.length() >= 20) ? firstLine.substring(0, 17) + "..." : firstLine;
                returnData.put("HTTPVersion", String.format("Unknown - Response not HTTP: FirstLine = [%s]", firstLine));
                returnData.put("StatusCode", "Unknown - Response not HTTP");
                return returnData;
            }

            // Get the header out first....
            String headerArea = rawData.substring(0, rawData.indexOf("\r\n\r\n"));
            // And the HTML body
            String bodyArea = rawData.substring(rawData.indexOf("\r\n\r\n") + 4);


            // Split & check first line
            String[] firstLineSplit = headerArea.split("\r")[0].split(" ");
            if (firstLineSplit.length < 3 || !firstLineSplit[0].contains("/")) {
                String firstLine = headerArea.split("\r")[0];
                firstLine = (firstLine.length() >= 20) ? firstLine.substring(0, 17) + "..." : firstLine;
                returnData.put("HTTPVersion", String.format("Unknown - Response header top line not in correct format: [%s]", firstLine));
                returnData.put("StatusCode", "Unknown - Response not formatted correctly");
                return returnData;  // No point in continuing with this farce....
            }


            // Finally, we can process the first line....
            returnData.put("HTTPVersion", firstLineSplit[0].split("[/]")[1]);
            returnData.put("StatusCode", firstLineSplit[1]);
            String statusText = "";
            for (int index = 2; index < firstLineSplit.length; index++) statusText += " " + firstLineSplit[index];
            statusText = statusText.trim();
            returnData.put("StatusText", statusText);

            // And do the rest of the header...  We do a for loop as we want to ignore the top line; it is just the HTTP protocol and version info
            String[] headerSplit = headerArea.split("\r\n");
            for (int index = 1; index < headerSplit.length; index++)
            {
                if (!headerSplit[index].contains(":"))
                    throw new Exception(String.format("Response contained invalid header line [%d]. No colon (:) present: [%s]", index, headerSplit[index]));
                else
                    returnData.put(headerSplit[index].split(":")[0].trim(), headerSplit[index].split(":")[1].trim());
            }

            // And finally the body...
            //
            // First, we need to know if the body is chunked. It if is we need to de-chunk it....
            //
            //
            //
            if (returnData.containsKey("Transfer-Encoding") && returnData.containsKey("Transfer-Encoding") && returnData.get("Transfer-Encoding") == "chunked")
            {
                //
                // So, we need to dechunk the data.....
                //
                // Data is chunked as follows
                // <Number of characters in hexaecimal>\r\n
                // <Characters in chunk>\r\n
                // this repeats until;
                // 0\r\n
                // \r\n
                boolean dechunkingFinished = false;
                String workingBody = "";
                String chunkHex;
                int chunkLength;
                while (!dechunkingFinished)
                {
                    // Itterates through the chunked body area

                    // Get the Chunk HEX
                    chunkHex = bodyArea.substring(0, bodyArea.indexOf("\r\n"));
                    bodyArea = bodyArea.substring(chunkHex.length() + 2, bodyArea.length() - (chunkHex.length() + 2));

                    //
                    try {
                        chunkLength = Integer.parseInt(chunkHex,16);
                    }
                    catch (Exception e) {
                        throw new Exception(String.format("[HTTP]DecodeResponse: Fatal error decoding chunked html body. Parsing Hex [%s] failed)", chunkHex),e);
                    }

                    if (chunkLength == 0) break;
                    workingBody += bodyArea.substring(0, chunkLength);
                    bodyArea = bodyArea.substring(chunkLength, bodyArea.length() - chunkLength);
                    if (!bodyArea.startsWith("\r\n")) {
                        throw new Exception(String.format("[HTTP]DecodeResponse: Fatal error decoding chunked html body. End of chunk length not CRLF!.  Chunk Length [%d], Data: [%s] ",chunkLength,bodyArea));
                    }
                    bodyArea = bodyArea.substring(2, bodyArea.length() - 2);
                }
                returnData.put("Body", workingBody);
            }
            else
                // No chunked so just grab the body
                returnData.put("Body", bodyArea);
            return returnData;
        }
        catch (Exception ex) {
            throw new Exception("[HTTP]DecodeResponse: Fatal error decoding raw response string header)", ex);
        }
    }
}

