
function createCredential() {
    const nickname = document.getElementById('nickname').value
    const randomChallenge = new Uint8Array(16);
    window.crypto.getRandomValues(randomChallenge);
    let createCredentialDefaultArgs = {
        publicKey: {
            rp: {
                name: "Cloud Wallet"
            },
            user: {
                id: new TextEncoder().encode(nickname),
                name: nickname,
                displayName: nickname
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
              document.getElementById('jwkpubkey').innerHTML =  JSON.stringify(subtleCryptoPublicKeyJWK);
              document.getElementById('didjwk').innerHTML =  "did:jwk:" + b64urltoa(JSON.stringify(subtleCryptoPublicKeyJWK));
              document.getElementById('output').style.display ='block';         
        })
        .catch((error) => {
            alert('Public key creation failed with error: ', error.message)
        })
}

function getCredential(textToSign) {
    let getCredentialArgs = {
        publicKey: {
            allowCredentials: [],
            timeout: 60000,
            challenge: new TextEncoder().encode(textToSign),
        }
    };
    navigator.credentials.get(getCredentialArgs)
        .then(async (assertedCredential) => {
            // Move data into Arrays incase it is super long
            let inputdid = document.getElementById('inputdid').value
            authenticatorData = new Uint8Array(assertedCredential.response.authenticatorData);
            clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
            signature = new Uint8Array(assertedCredential.response.signature);
            window.location.replace("https://excid-io.github.io/fido2-sign/rp.html"
             + "?a=" + Uint8Tob64url(authenticatorData) 
             + "&c="+ Uint8Tob64url(clientDataJSON) 
             + "&s=" + Uint8Tob64url(signature) +
            + "&d=" + inputdid + "&state=" + textToSign);
        })
        .catch((error) => {
            alert('Signature creation failed with error: ', error.message)
            console.log("Error", error)
        })
}

function b64urltoa(buf) {
    return btoa(buf)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}


function Uint8Tob64url(buf) {
    return btoa(String.fromCharCode.apply(null,buf))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

function b64urlToUint8(buf) {
    return encoder.encode(atob(buf
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")));
}

function sign(){
    let params = (new URL(document.location)).searchParams;
    const textToSign = params.get("state")
    getCredential(textToSign)
    //crypto.subtle.digest('SHA-256', new TextEncoder().encode(textToSign)).then((textToSignHash) => {getCredential(textToSignHash)})
}

function verify()
{
    const textToVerify = document.getElementById('textToVerify').value
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(textToVerify)).then((textToVerifyHash) => {
        _verify(textToVerifyHash).then((result)=>{alert("Verification output: " + result)});
    });
    
}


async function  _verify(textToVerify)
{
    //Step 1 verify clientDataJSON
    const clientDataObj = JSON.parse(new TextDecoder().decode(clientDataJSON))
    challenge = b64URLenc(String.fromCharCode.apply(null,new Uint8Array(textToVerify)))
    if (clientDataObj.challenge != challenge){
        return "ClientDataJSON validation failed."
    }
    let clientDataJSON_sha256 = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON));
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
    if (result){
        return "verification succeeded"
    }else{
        return "signature validation failed"
    }
}


