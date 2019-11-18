var video = document.createElement("video");
var canvasElement = document.createElement("canvas");
var canvas = canvasElement.getContext("2d");

navigator.mediaDevices.getUserMedia({
  video: {
    facingMode: "environment"
  }
}).then(function(stream) {
  video.srcObject = stream;
  video.setAttribute("playsinline", true);
  video.play();
  requestAnimationFrame(tick);
});

function decipher(ciphertext) {
  key = "soyunaclavesoyun"

  var ciphertext = CryptoJS.enc.Base64.parse(ciphertext);
  console.log("CIPHERTEXT-BYTE")
  console.log(ciphertext)
  // split iv and ciphertext
  var iv = ciphertext.clone();
  iv.sigBytes = 16;
  iv.clamp();
  ciphertext.words.splice(0, 4); // delete 4 words = 16 bytes
  ciphertext.sigBytes -= 16;

  console.log("IV: "+ iv)
  console.log("CT: " + ciphertext)

  var key = CryptoJS.enc.Utf8.parse(key);

  // decryption
  var decrypted = CryptoJS.AES.decrypt({ciphertext: ciphertext}, key, {
    iv: iv,
    mode: CryptoJS.mode.CFB
  });

  console.log(decrypted)
  console.log ( decrypted.toString(CryptoJS.enc.Latin1) );
}

/*function _base64ToArrayBuffer(base64) {
  var binary_string = window.atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}*/

function ascii_to_hexa(str) {
  var arr1 = [];
  for (var n = 0, l = str.length; n < l; n++) {
    var hex = Number(str.charCodeAt(n)).toString(16);
    arr1.push(hex);
  }
  return arr1.join('');
}

function base64toHEX(base64) {
  var raw = atob(base64);
  var HEX = '';
  for (i = 0; i < raw.length; i++) {
    var _hex = raw.charCodeAt(i).toString(16)
    HEX += (_hex.length == 2 ? _hex : '0' + _hex);
  }
  return HEX.toUpperCase();
}

function tick() {
  let isDone = false;
  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    canvasElement.height = video.videoHeight;
    canvasElement.width = video.videoWidth;
    canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);
    var imageData = canvas.getImageData(0, 0, canvasElement.width, canvasElement.height);
    var code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: "dontInvert",
    });
    if (code) {
      console.log(code.data);
      console.log("_____________ DECHIPERING ___________");
      decipher(code.data)
      console.log("_____________ ----------- ___________");

      document.getElementById('password').setAttribute("text", "value: " + code.data + ";color:black");
      video.pause();
      delete video;
      delete canvas;
      delete canvasElement;
      isDone = true;
    }
  }
  if (!isDone) {
    requestAnimationFrame(tick);
  }
}
