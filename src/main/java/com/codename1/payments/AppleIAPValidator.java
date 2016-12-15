/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.codename1.payments;

import com.codename1.io.ConnectionRequest;
import com.codename1.io.JSONParser;
import com.codename1.io.NetworkEvent;
import com.codename1.payment.Receipt;
import com.codename1.processing.Result;
import com.codename1.ui.events.ActionListener;
import com.codename1.util.Callback;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author shannah
 */
public class AppleIAPValidator extends IAPValidator {

    private static final String sandboxHost = "sandbox.itunes.apple.com";
    private static final String liveHost = "buy.itunes.apple.com";
    private static final String path = "/verifyReceipt";

    private static final String prodPath = "https://" + liveHost + path;
    private static final String sandboxPath = "https://" + sandboxHost + path;

    
    private class ReceiptHolder {
        Receipt[] receipts;
    }
    
    private class ExceptionHolder {
        Throwable ex;
    }
    
    @Override
    public Receipt[] validate(final Receipt receipt) throws IOException {
        final ReceiptHolder h = new ReceiptHolder();
        final ExceptionHolder eh = new ExceptionHolder();
        
        validatePurchase(getAppleSecret(), receipt.getOrderData(), new Callback<Response>() {

            @Override
            public void onSucess(Response t) {
                Receipt[] receipts = t.getReceipts(false);
                List<Receipt> out = new ArrayList<Receipt>();
                
                // Get only receipts matching the transaction id
                for (Receipt r : receipts) {
                    //System.out.println("Now checking "+ r +" against "+receipt);
                    //if (r.getTransactionId().equals(receipt.getTransactionId())) {
                        out.add(r);
                    //}
                }
                h.receipts = out.toArray(new Receipt[out.size()]);
            }

            @Override
            public void onError(Object o, Throwable thrwbl, int i, String string) {
                eh.ex = thrwbl;
            }
            
        });
        
        if (h.receipts != null) {
            return h.receipts;
        } else if (eh.ex != null) { 
            if (eh.ex instanceof IOException) {
                throw (IOException)eh.ex;
            } else {
                throw new RuntimeException(eh.ex);
            }
        } else {
            throw new RuntimeException("Async network requests not supported.  Thread "+Thread.currentThread());
        }
        
    }

    private static class TimeIndex {

        long time;
        int index;
        
        TimeIndex(long time, int index) {
            this.time=time;
            this.index=index;
        }
    }

    private static Long getSubscriptionExpireDate(Result data) {
        if (data.get("expires_date_ms") != null) {
            return data.getAsLong("expires_date_ms");
        }

        if (data.get("expires_date") != null) {
            return data.getAsLong("expires_date");
        }
        return null;

    }

    private static class Response {

        int status;
        String message;
        boolean isValidated;
        private Result purchaseData;

        public Receipt[] getReceipts(boolean ignoreExpired) {
            if (purchaseData.get("receipt") == null) {
                return null;
            }
            Result receipts = Result.fromContent((Map) purchaseData.get("receipt"));
            List<Receipt> data = new ArrayList<Receipt>();
            if (receipts.get("in_app") != null) {
                Map<String, TimeIndex> tids = new HashMap<String, TimeIndex>();
                
                List list = (List) receipts.getAsArray("in_app");
                Object lri = receipts.get("latest_receipt_info");
                if (lri != null) {
                    list.addAll(receipts.getAsArray("latest_receipt_info"));
                }
                for (int i = 0, len = list.size(); i < len; i++) {
                    Result item = Result.fromContent((Map) list.get(i));
                    String tid = item.getAsString("original_transaction_id");
                    long pdate = item.getAsLong("purchase_date_ms");
                    Long exp = getSubscriptionExpireDate(item);
                    int index = data.size();

                    if (ignoreExpired && exp != null && new Date().getTime() - exp >= 0) {
                        continue;
                    }

                    if (tids.containsKey(tid) && tids.get(tid).time < pdate) {
                        index = tids.get(tid).index;
                    }
                    tids.put(tid, new TimeIndex(pdate, index));
                    Receipt pd = new Receipt();
                    //pd.set= receipts.getAsString("bundle_id");
                    pd.setTransactionId(item.getAsString("transaction_id"));
                    pd.setSku(item.getAsString("product_id"));
                    pd.setPurchaseDate(new Date(pdate));
                    if (item.get("cancellation_date") != null) {
                        pd.setCancellationDate(new Date(item.getAsLong("cancellation_date")));
                    }
                    pd.setQuantity(item.getAsInteger("quantity"));
                    if (exp != null) {
                        pd.setExpiryDate(new Date(exp));
                    }
                    
                    if (purchaseData.get("latest_receipt") != null) {
                        System.out.println("latest_receipt is not null");
                        pd.setOrderData(purchaseData.getAsString("latest_receipt"));
                    } else {
                        System.out.println("latest_receipt is null");
                    }
                    if (index < data.size()) {
                        data.set(index, pd);
                    } else {
                        data.add(pd);
                    }
                    //System.out.println("Data now "+data);
                }
            }

            return data.toArray(new Receipt[data.size()]);

        }

    }

    /**
     * Error codes for IAP validation REST service
     */
    private static Object[] errorMap = new Object[]{
        21000, "The App Store could not read the JSON object you provided.",
        21002, "The data in the receipt-data property was malformed.",
        21003, "The receipt could not be authenticated.",
        21004, "The shared secret you provided does not match the shared secret on file for your account.",
        21005, "The receipt server is not currently available.",
        21006, "This receipt is valid but the subscription has expired. When this status code is returned to your server, the receipt data is also decoded and returned as part of the response.",
        21007, "This receipt is a sandbox receipt, but it was sent to the production service for verification.",
        21008, "This receipt is a production receipt, but it was sent to the sandbox service for verification.",
        2, "The receipt is valid, but purchased nothing."};

    // The receipts keys in iOS receipts
//        var REC_KEYS = {
//                IN_APP: 'in_app',
//                LRI: 'latest_receipt_info',
//                BUNDLE_ID: 'bundle_id',
//                TRANSACTION_ID: 'transaction_id',
//                PRODUCT_ID: 'product_id',
//                ORIGINAL_PURCHASE_DATE_MS: 'original_purchase_date_ms',
//                EXPIRES_DATE_MS: 'expires_date_ms',
//                EXPIRES_DATE: 'expires_date',
//                CANCELLATION_DATE: 'cancellation_date',
//                PURCHASE_DATE_MS: 'purchase_date_ms'
//        };
    private String getErrorMessageForCode(int code) {

        int len = errorMap.length;
        for (int i = 0; i < len; i += 2) {
            if (((Integer) errorMap[i]) == code) {
                return (String) errorMap[i + 1];
            }
        }
        return null;
    }

    Response validatedData;

    void validatePurchaseImpl(final String url, String secret, final String receipt, final Callback<Response> response) {
        final boolean isSandbox = url.equals(sandboxPath);
        Map content = new HashMap();
        content.put("receipt-data", receipt);
        if (secret == null) {
            secret = System.getProperty("iap.applePassword", null);
        }
        if (secret != null) {
            content.put("password", secret);
        }

        final Map fContent = content;
        final ConnectionRequest request = new ConnectionRequest() {

            @Override
            protected void buildRequestBody(OutputStream os) throws IOException {
                os.write(Result.fromContent(fContent).toString().getBytes("UTF-8"));
            }

        };

        final String fSecret = secret;
        request.addRequestHeader("Content-type", "application/json");
        request.addRequestHeader("Accept", "application/json");
        request.setUrl(url);
        request.setHttpMethod("POST");
        request.setPost(true);
        request.setFailSilently(true);
        request.setReadResponseForErrors(true);
        request.addResponseListener(new ActionListener<NetworkEvent>() {

            @Override
            public void actionPerformed(NetworkEvent evt) {
                try {
                    System.out.println("Response: "+new String(request.getResponseData(), "UTF-8"));
                } catch (Exception ex) {}
                if (request.getResponseCode() >= 200 && request.getResponseCode() < 300) {
                    try {
                        JSONParser p = new JSONParser();
                        Map m = p.parseJSON(new InputStreamReader(new ByteArrayInputStream(request.getResponseData()), "UTF-8"));
                        Result res = Result.fromContent(m);
                        int dStatus = res.getAsInteger("status");
                        if (dStatus > 0 && ((!isSandbox && dStatus != 21007 && dStatus != 21002) || isSandbox)) {
                            // We're in the production, we got an error, and the error
                            // wasn't that it was a sandbox receipt
                            // Or we are in the sandbox and got an error.
                            String eMessage = getErrorMessageForCode(dStatus);
                            if (eMessage == null) {
                                eMessage = "Unknown";
                            }

                            validatedData = new Response();
                            validatedData.status = dStatus;
                            validatedData.message = eMessage;

                            applyResponseData(validatedData, res);
                            validatedData.isValidated = false;
                            response.onError(AppleIAPValidator.this, new IOException(eMessage), dStatus, eMessage);
                            return;

                        } 
                        if (!isSandbox && (dStatus == 21007 || dStatus == 21002)) {
                            // We're in production, and we got an error other than 
                            // it being a sandbox receipt
                            //validatedData.isValidated = false;
                            validatePurchaseImpl(sandboxPath, fSecret, receipt, response);
                            return;
                        } 
                        //String latestReceipt = res.getAsString("latest_receipt");
                        
                        validatedData = new Response();
                        applyResponseData(validatedData, res);
                        
                        validatedData.isValidated = true;
                        response.onSucess(validatedData);
                    } catch (Throwable ex) {
                        if (!isSandbox) {
                            validatedData.isValidated = false;
                            validatePurchaseImpl(sandboxPath, fSecret, receipt, response);
                            return;
                        } else {
                            ex.printStackTrace();
                            response.onError(AppleIAPValidator.this, ex, 1, ex.getMessage());
                            return;
                        }
                    } 

                } else {
                    response.onError(AppleIAPValidator.this, new IOException("Failed to connect"), evt.getResponseCode(), "Unexpected response code "+evt.getResponseCode());
                }
            }

        });
        request.addToQueueAndWait();

    }

    void validatePurchase(String secret, String receipt, Callback<Response> response) {
        validatePurchaseImpl(prodPath, secret, receipt, response);
    }

    private static void applyResponseData(Response data, Result res) {
        data.purchaseData = res;
    }

}
