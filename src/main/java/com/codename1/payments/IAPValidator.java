/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.codename1.payments;


import com.codename1.payment.Receipt;
import java.io.IOException;


/**
 * 
 * @author shannah
 */
public abstract class IAPValidator {
    private String appleSecret;
    private String googleClientId;
    private String googlePrivateKey;
    
    public static IAPValidator getValidatorForPlatform(String storeCode) {
        if (Receipt.STORE_CODE_ITUNES.equals(storeCode)) {
                return new AppleIAPValidator();
        } else if (Receipt.STORE_CODE_PLAY.equals(storeCode)) {
            return new GooglePlayValidator();
        } else {
            return null;
        }
    }
    
    
    public String getAppleSecret() {
        return appleSecret;
    }
    
    public void setAppleSecret(String secret) {
        appleSecret = secret;
    }
    
    public abstract Receipt[] validate(Receipt receipt) throws IOException;
    

    /**
     * @return the googleClientId
     */
    public String getGoogleClientId() {
        return googleClientId;
    }

    /**
     * @param googleClientId the googleClientId to set
     */
    public void setGoogleClientId(String googleClientId) {
        this.googleClientId = googleClientId;
    }

    /**
     * @return the googlePrivateKey
     */
    public String getGooglePrivateKey() {
        return googlePrivateKey;
    }

    /**
     * @param googlePrivateKey the googlePrivateKey to set
     */
    public void setGooglePrivateKey(String googlePrivateKey) {
        this.googlePrivateKey = googlePrivateKey;
    }

    
    
}
