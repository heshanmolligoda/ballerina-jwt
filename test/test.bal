package test;

import ballerina.lang.system;
import jwt;

function main (string[] args) {
    json userInfo = {email : "irshadn@wso2.com"};
    var token, _ = jwt:encode(userInfo, "Some Long Shared Key Goes here for JWT encryption", "HS256");

    system:println(token);

    var result, _ = jwt:decode(token);
    system:println(result.email);
}
