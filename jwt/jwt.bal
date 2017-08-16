package jwt;

import ballerina.utils;
import ballerina.lang.strings;
import ballerina.lang.jsons;
import ballerina.doc;

@doc:Description {value:"Generate JWT token."}
@doc:Param {value:"payload: payload json"}
@doc:Param {value:"secred: Secret key"}
@doc:Param {value:"algorithm: Algorithm to use for hashing"}
@doc:Return {value:"token: Generated token"}
@doc:Return {value:"error: Returned when an JWT exception occured"}
function encode (json payload, string secret, string algorithm) (string token, JWTError error){
    if(payload == null){
        error = {msg: "Payload cannot be null"};
        return ;
    }

    int secretLength = strings:length(secret);
    if(secretLength < 32){
        error = {msg: "secret length cannot be less than 32 bytes. Current length: " + secretLength};
        return ;
    }
    json header = {};

    if(algorithm == "HS256"){
        header = {
                     "alg": "HS256",
                     "typ": "JWT"
                 };
    }else{
        // TODO: support for other algorithm
        error = {msg: "Invalid/Non-supported algorithm specified"};
        return;
    }
    string headerEncode = utils:base64encode(strings:valueOf(header));
    string payloadEncode = utils:base64encode(strings:valueOf(payload));
    string s = headerEncode + "." + payloadEncode;
    string signature = utils:getHmac(s, secret, "SHA256");
    token = s + "." +signature;

    return;
}

@doc:Description {value:"Returns payload json from JWT"}
@doc:Param {value:"token: JWT Token"}
@doc:Return {value:"token: Generated token"}
@doc:Return {value:"error: Returned when an JWT exception occured"}
function decode (string token) (json payload, JWTError  error){
    //TODO: verification of payload+header with signature
    string[] data = strings:split(token,"\\.");
    if(data.length != 3){
        error = {msg : "Invalid Token"};
        return;
    }
    string payloadString = utils:base64decode(data[1]);
    payload = jsons:parse(payloadString);
    return;
}

@doc:Description {value:"Returns user's email contained in JWT"}
@doc:Param {value:"token: JWT Token"}
@doc:Return {value:"emai: user email"}
function getEmail (string jwtToken, string key)(string email)  {

    var payload,_ = decode(jwtToken);
    email,_ =(string) payload[key];
    return;
}