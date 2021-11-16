// https://jswheeler.medium.com/integrating-aws-guardduty-with-atlassian-opsgenie-using-lambda-dd2fed16621a
//
var AWS = require('aws-sdk');
exports.handler = (event, context, callback) => {
    console.log(event);
    console.log(context);
    var sns = new AWS.SNS();
    if ( event.detail.severity > 0.1 && event.detail.severity < 3.9 ) {
        event.detail.priority = "P3";
    } else if (event.detail.severity > 3.9 && event.detail.severity < 6.9 ) {
        event.detail.priority = "P2";
    } else if (event.detail.severity > 6.9 && event.detail.severity < 9.0 ) {
        event.detail.priority = "P1";
    }
    sns.publish({Message: JSON.stringify(event), TopicArn: process.env.topic_arn }, function(err, data) {
        if(err) {
            console.log('error publishing to SNS');
            context.fail(err);
        } else {
            console.log('message published to SNS');
            context.succeed(null, data);
        }
    });
    return event;
};

