package jwt;

import ballerina.lang.errors;

struct JWTError{
    string msg;
    errors:Error cause;
}