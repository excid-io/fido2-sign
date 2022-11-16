var subtleCryptoPublicKey;
var authenticatorData;
var clientDataJSON;
var signature;

function createCredential() {
    const randomChallenge = new Uint8Array(16);
    window.crypto.getRandomValues(randomChallenge);
    let createCredentialDefaultArgs = {
        publicKey: {
            rp: {
                name: "Cloud Wallet"
            },
            user: {
                id: new TextEncoder().encode("demo-user"),
                name: "Demo User",
                displayName: "Demo User"
            },
            pubKeyCredParams: [
                {
                  alg: -7,
                  type: "public-key"
                }
              ],
            authenticatorSelection: {
                residentKey: "required",
                userVerification: "discouraged"
            },
            attestation: "none",
            timeout: 60000,
            challenge: randomChallenge,
        }
    };
    navigator.credentials.create(createCredentialDefaultArgs)
        .then(async (newCredential) => {
            let publicKey = newCredential.response.getPublicKey()
            subtleCryptoPublicKey = await  window.crypto.subtle.importKey(
                "spki",
                publicKey,
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                ["verify"]
              );

            let subtleCryptoPublicKeyJWK = await window.crypto.subtle.exportKey(
                "jwk",
                subtleCryptoPublicKey
              );
              document.getElementById('jwkpubkey').innerHTML =  JSON.stringify(subtleCryptoPublicKeyJWK)         
        })
}

function getCredential(textToSign) {
    let getCredentialArgs = {
        publicKey: {
            allowCredentials: [],
            timeout: 60000,
            challenge: textToSign,
        }
    };
    navigator.credentials.get(getCredentialArgs)
        .then(async (assertedCredential) => {
            // Move data into Arrays incase it is super long
            authenticatorData = new Uint8Array(assertedCredential.response.authenticatorData);
            clientDataJSON = new TextDecoder().decode(new Uint8Array(assertedCredential.response.clientDataJSON));
            signature = new Uint8Array(assertedCredential.response.signature);
            document.getElementById('authenticatorData').innerHTML =  btoa(String.fromCharCode.apply(null,authenticatorData))
            document.getElementById('clientDataJSON').innerHTML =  clientDataJSON
            document.getElementById('signature').innerHTML =  btoa(String.fromCharCode.apply(null,signature))
        })
        .catch((error) => {
            console.log('FAIL', error)
        })
}

function b64URLenc(buf) {
    return btoa(buf)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

function sign(){
    const textToSign = document.getElementById('textToSign').value
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(textToSign)).then((textToSignHash) => {getCredential(textToSignHash)})
}

function verify()
{
    const textToVerify = document.getElementById('textToVerify').value
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(textToVerify)).then((textToVerifyHash) => {
        const clientDataObj = JSON.parse(clientDataJSON)        
        clientDataObj.challenge = b64URLenc(String.fromCharCode.apply(null,new Uint8Array(textToVerifyHash)))
        console.log(clientDataObj)
        clientData = JSON.stringify(clientDataObj);
        _verify(clientData).then((result)=>{alert("Signature verification..." + result)});
    });
    
}


async function  _verify(clientData)
{
    console.log(clientData)
    let clientDataJSON_sha256 = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientData)));
    let signatureBase = new Uint8Array(authenticatorData.length + clientDataJSON_sha256.length);
    signatureBase.set(authenticatorData);
    signatureBase.set(clientDataJSON_sha256, authenticatorData.length);
    
    //https://gist.github.com/philholden/50120652bfe0498958fd5926694ba354
    var rStart = signature[4] === 0 ? 5 : 4;
    var rEnd = rStart + 32;
    var sStart = signature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
    var r = signature.slice(rStart, rEnd);
    var s = signature.slice(sStart);
    var rawSignature = new Uint8Array([...r, ...s]);
    let result = await window.crypto.subtle.verify(
        {
          name: "ECDSA",
          hash: {name: "SHA-256"},
        },
        subtleCryptoPublicKey,
        rawSignature,
        signatureBase
      );
    return result
}


