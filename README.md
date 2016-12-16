# Codename One IAP Validator

This library provides receipt validation for Google Play and iTunes connect.  It is meant to be used on the "server-side" in a JavaEE project.

## Dependencies

This library depends on the the [cn1-compatlib project](https://github.com/shannah/cn1-compatlib), which provides some classes from the Codename One
API for use in server projects.  In particular, it provides the `Receipt` class which is used for input 
and output of the validator.

I used the compatlib rather than using the standard JavaEE classes so that it would be easier to port to the client-side if the need arose.

## Installation

~~~~
$ clone https://github.com/shannah/cn1-iap-validator
$ cd cn1-iap-validator
$ ant install
~~~~

The "ant install" step will download the [cn1-compatlib](https://github.com/shannah/cn1-compatlib) project into the dependencies directory, then build it and install it to your local maven repo so that it is available as a transitive dependency.

**Using in a Maven Project**

~~~~
<dependency>
    <groupId>com.codename1</groupId>
    <artifactId>cn1-iap-validator</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
~~~~

**Using in Non-Maven Project**

Add the [cn1-iap-validator-1.0-SNAPSHOT.jar](bin/cn1-iap-validator-1.0-SNAPSHOT.jar) and [CN1-Compatlib.jar](bin/CN1-Compatlib.jar) to your classpath.

## Usage

~~~
IAPValidator validator = IAPValidator.getValidatorForPlatform(receipt.getStoreCode());
if (validator == null) {
   // no validators were found for this store
   // Do custom validation
} else {
    validator.setAppleSecret(APPLE_SECRET);
    validator.setGoogleClientId(GOOGLE_DEVELOPER_API_CLIENT_ID);
    validator.setGooglePrivateKey(GOOGLE_DEVELOPER_PRIVATE_KEY);
    Receipt[] result = validator.validate(receipt);
    ...
}
~~~

The `result` array will include receipts returned from the validation services, but with the expiry date filled in. On iTunes this will include many receipts other than the receipt passed to it. 
  
If there is no receipt in `result` that matches the transaction ID of `receipt`, then the original receipt is dead.  You should delete it from your data source, and update/insert all other receipts in `result`.

## License

Apache 2.0

## Credits

Written by Steve Hannah

