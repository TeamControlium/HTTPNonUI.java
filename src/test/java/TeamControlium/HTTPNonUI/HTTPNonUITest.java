package TeamControlium.HTTPNonUI;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class HTTPNonUITest {

    HTTPNonUI httpNonUI;
    @BeforeEach
    void setUp() {
        httpNonUI = new HTTPNonUI();
    }

    @AfterEach
    void tearDown() {
    }

    // Verify we can browse to a URL with Selenium
    @org.junit.jupiter.api.Test
    void VerifyBrowseToWorks() {
        Map<String,String> response = new HashMap<String,String>();
        try {
            String header = "GET " + "/" + " HTTP/1.1\r\n" +
                    "Host: "+ "www.google.com" +" \r\n" +
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n" +
                    "Connection: close\r\n\r\n";

            response = httpNonUI.sendWebRequest("www.google.com",80,header);

        }
        catch (Exception e) {

        }

        int aa = response.get("Body").length();
        String hh = response.get("Body");


        boolean h = response.containsKey("Hello");


        // Assertions.assertEquals("Google", pageTitle, "Page title correct");
    }


}