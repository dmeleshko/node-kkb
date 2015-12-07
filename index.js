var Crypto = require('crypto');
var fs = require('fs');
var xml2js = require('xml2js');
var Buffer = require('buffer').Buffer;

// Функции для работы с цифровой подписью

function sign(data, privateKeyFile, privateKeyPass, cb) {
    fs.readFile(privateKeyFile, (err, pkData) => {
        if(err) return cb(err, "Error reading private key file");
        var pk = {
            key: pkData.toString('ascii'),
            passphrase: privateKeyPass
        };
        var sign = Crypto.createSign('RSA-SHA1');
        sign.update(data);
        try {
            return cb(false, sign.sign(pk, 'base64'));
        } catch (e) {
            return cb(true, e.message);
        }
    })
}

function verify (data, sign, publicKeyFile, cb) {
    fs.readFile(publicKeyFile, (err, pubData) => {
        if(err) return cb(err, "Error reading public key file");
        var pub = pubData.toString('ascii');
        var verify = Crypto.createVerify('RSA-SHA1');
        verify.update(data);
        return cb(false, verify.verify(pub, sign, 'base64'));
    });
}

// Функции для работы с xml

function merchantObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency) {
    return {
        '$': {
            cert_id: cert_id,
            name: merchant_name
        },
        order: [{
            '$': {
                order_id: order_id,
                amount: order_amount,
                currency: order_currency || 398
            },
            department: [{
                '$': {
                    merchant_id: merchant_id,
                    amount: order_amount
                }
            }]
        }]
    };
}

function merchantXml(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency) {
    var merObj = merchantObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency);
    var builder = new xml2js.Builder({rootName: 'merchant', headless: true, renderOpts: {'pretty': false}});
    return builder.buildObject(merObj);
}

function documentObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency, signBase64) {
    return {
        merchant: merchantObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency),
        merchant_sign: {
            '$': {
                type: 'RSA'
            },
            '_': signBase64
        }
    };
}

function documentXml(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency, signBase64) {
    var docObj = documentObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency, signBase64);
    var builder = new xml2js.Builder({rootName: 'document', headless: true, renderOpts: {'pretty': false}});
    return builder.buildObject(docObj);
}

function getSignedOrderXml(config, order_id, order_amount, order_currency, cb) {
    try {
        var merXml = merchantXml(config.cert_id, config.merchant_id, config.merchant_name, order_id, order_amount, order_currency);
        sign(merXml, config.privateKeyFile, config.privateKeyPass, (err, data) => {
            if(err) return cb(err, data);
            return cb(false, documentXml(config.cert_id, config.merchant_id, config.merchant_name, order_id, order_amount, order_currency, data));
        });
    } catch (e) {
        return cb(true, e.message);
    }
}

function getSignedOrderBase64(config, order_id, order_amount, order_currency, cb) {
    getSignedOrderXml(config, order_id, order_amount, order_currency, (err, data) => {
        if(err) return cb(err, data);
        var buf = new Buffer(data);
        return cb(false, buf.toString('base64'));
    });
}

function splitBankAnswer(xmlString, cb) {
    var parser = new xml2js.Parser();
    parser.parseString(xmlString, (err, data) => {
        if(err) return cb(err, data);
        console.dir(data);
    });
}

function processBankAnswer(config, xmlString) {

}

exports.getSignedOrderBase64 = getSignedOrderBase64;
exports.splitBankAnswer = splitBankAnswer;
