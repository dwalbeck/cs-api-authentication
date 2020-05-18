'use strict';

const async = require('async');
const redis = require('redis');

/* NOTE: This script requires the following variables are set as system variables with the correct values
    process.env.REDIS_HOST
    process.env.REDIS_PORT
    process.env.REDIS_DB
 */

const sessionTTL = 1800; // seconds that token is valid for 60 * 30 => 30 mins

exports.handler = async (event, context, callback) => {
    // set variables
    //const header = JSON.parse(event);
    const token = event.authorizationToken;
    const serviceDomain = context.Url;
    let urlParts = serviceDomain.split('.');
    let service = urlParts[0];
    let awsParts = event.methodArn.split(':');
    let apiGatewayArnTmp = awsParts[5].split('/');
    let awsAccountId = awsParts[4];
    let apiOptions = {
        region: awsParts[3],
        restApiId: apiGatewayArnTmp[0],
        stage: apiGatewayArnTmp[1],
        method: apiGatewayArnTmp[2]
    };
    const method = apiGatewayArnTmp[2];
    let resource = '/'; // resource root
    if (apiGatewayArnTmp[3]) {
        resource += apiGatewayArnTmp.slice(3, apiGatewayArnTmp.length).join('/');
    }
    let accessResult = 'Deny';
    let options = {
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT || 6397,
        db: process.env.REDIS_DB || 1
    };
    let retData;
    const client = redis.createClient(options);

    client.on('error', function(err) {
        callback('An error occurred with Redis - '+err);
    });

    async.waterfall([
        function(cb) {
            // check against cache for record
            client.get(token, function(err, payload) {
                if (err) { return cb('Error querying Redis - '+err); }
                if (payload === '' || payload === undefined) { return cb('No matching record found for token'); }
                retData.context = JSON.parse(payload);

                cb(null, payload);
            });
        },
        function(payload, cb) {
            // reset the expire timeout
            client.expire([token, sessionTTL], function(err) {
                if (err) { return cb('Error while trying to reset TTL - '+err); }
                cb(null);
            });
        },
        function(cb) {
            // determine read-only or write access
            let accessNeeded = 'readonly';
            if (method === 'POST' || method === 'DELETE' || method === 'PUT') {
                accessNeeded = 'write';
            }

            // verify permissions to access service requested
            // cycle through services
            async.each(retData.context["X-Permissions"].services, function(currentService, cback) {
                if (service === currentService.service_subdomain) {
                    if (accessNeeded === 'write' && currentService.service_write > 0 || accessNeeded === 'readonly') {
                        accessResult = 'Allow';
                    }
                }
                cback();

            }, function(err) {
                if (err) { return cb(err); }
                /*if (accessResult === 'Deny') {
                    return cb('Application does not have rights for the requested service '+service+'. Access denied');
                }*/
                cb(null);
            });
        }

    ], function(err) {
        client.end(true);
        if (err) {
            return callback(err);
        }
        let policy = new AuthPolicy(principalId, awsAccountId, apiOptions);
        if (accessResult === 'Deny') {
            policy.denyAllMethods();
        } else {
            let authResponse = policy.build();
            authResponse.context = retData;
        }
        callback(retData);
    });
};

function AuthPolicy(principal, awsAccountId, apiOptions) {
    this.awsAccountId = awsAccountId;
    this.principalId = principal;
    this.version = "2012-10-17";
    this.restApiId = ((!apiOptions || !apiOptions.restApiId) ? "*" : apiOptions.restApiId);
    this.region = ((!apiOptions || !apiOptions.region) ? "*" : apiOptions.region);
    this.stage = ((!apiOptions || !apiOptions.stage) ? "*" : apiOptions.stage);

}

AuthPolicy.HttpVerb = {
    GET     : "GET",
    POST    : "POST",
    PUT     : "PUT",
    PATCH   : "PATCH",
    HEAD    : "HEAD",
    DELETE  : "DELETE",
    OPTIONS : "OPTIONS",
    ALL     : "*"
};

AuthPolicy.prototype = (function() {
    const addMethod = function(effect, verb, resource, conditions) {
        if (verb !== "*" && !AuthPolicy.HttpVerb.hasOwnProperty(verb)) {
            throw new Error("Invalid HTTP method " + verb);
        }
        let cleanedResource = resource;
        if (resource.substring(0, 1) === "/") {
            cleanedResource = resource.substring(1, resource.length);
        }
        let resourceArn = "arn:aws:execute-api:" +
            this.region + ":" +
            this.awsAccountId + ":" +
            this.restApiId + "/" +
            this.stage + "/" +
            verb + "/" +
            cleanedResource;
        if (effect.toLowerCase() === "allow") {
            this.allowMethods.push({
                resourceArn: resourceArn,
                conditions: conditions
            });
        } else if (effect.toLowerCase() === "deny") {
            this.denyMethods.push({
                resourceArn: resourceArn,
                conditions: conditions
            })
        }
    };

    const getEmptyStatement = function(effect) {
        effect = effect.substring(0, 1).toUpperCase() + effect.substring(1, effect.length).toLowerCase();
        return {
            Action: "execute-api:Invoke",
            Effect: effect,
            Resource: []
        };
    };

    const getStatementsForEffect = function(effect, methods) {
        let statements = [];

        if (methods.length > 0) {
            let statement = getEmptyStatement(effect);

            for (let i = 0; i < methods.length; i++) {
                let curMethod = methods[i];
                if (curMethod.conditions === null || curMethod.conditions.length === 0) {
                    statement.Resource.push(curMethod.resourceArn);
                } else {
                    let conditionalStatement = getEmptyStatement(effect);
                    conditionalStatement.Resource.push(curMethod.resourceArn);
                    conditionalStatement.Condition = curMethod.conditions;
                    statements.push(conditionalStatement);
                }
            }

            if (statement.Resource !== null && statement.Resource.length > 0) {
                statements.push(statement);
            }
        }
        return statements;
    };

    return {
        constructor: AuthPolicy,
        allowAllMethods: function() {
            addMethod.call(this, "allow", "*", "*", null);
        },
        denyAllMethods: function() {
            addMethod.call(this, "deny", "*", "*", null);
        },
        allowMethod: function(verb, resource) {
            addMethod.call(this, "allow", verb, resource, null);
        },
        denyMethod : function(verb, resource) {
            addMethod.call(this, "deny", verb, resource, null);
        },
        allowMethodWithConditions: function(verb, resource, conditions) {
            addMethod.call(this, "allow", verb, resource, conditions);
        },
        denyMethodWithConditions : function(verb, resource, conditions) {
            addMethod.call(this, "deny", verb, resource, conditions);
        },
        build: function() {
            if ((!this.allowMethods || this.allowMethods.length === 0) && (!this.denyMethods || this.denyMethods.length === 0)) {
                throw new Error("No statements defined for the policy");
            }

            let policy = {};
            policy.principalId = this.principalId;
            let doc = {};
            doc.Version = this.version;
            doc.Statement = [];

            doc.Statement = doc.Statement.concat(getStatementsForEffect.call(this, "Allow", this.allowMethods));
            doc.Statement = doc.Statement.concat(getStatementsForEffect.call(this, "Deny", this.denyMethods));

            policy.policyDocument = doc;

            return policy;
        }
    };
})();



