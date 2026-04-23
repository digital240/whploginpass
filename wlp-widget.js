(function() {

// WLP config is set globally before this script loads (in theme.liquid)
// var WLP = { backendUrl, shopDomain, storeName } - set by inline script

var wlpState = { phone: "", timerInt: null };

// ============================================================
// WLP SESSION - GoKwik-style token system
// Works on ALL Shopify plans - no Multipass needed!
// ============================================================

var WLP_TOKEN_KEY  = "wlp_token";
var WLP_DEVICE_KEY = "wlp_device_id";

function wlpGetDeviceId() {
  var id = localStorage.getItem(WLP_DEVICE_KEY);
  if (!id) { id = "wlp_" + Date.now() + "_" + Math.random().toString(36).substr(2,12); localStorage.setItem(WLP_DEVICE_KEY, id); }
  return id;
}

function wlpSaveSession(wlpToken, phone) {
  // Save token to cookie (30 days) - readable by Shopify theme
  var expires = new Date();
  expires.setDate(expires.getDate() + 30);
  document.cookie = WLP_TOKEN_KEY + "=" + encodeURIComponent(wlpToken) + "; expires=" + expires.toUTCString() + "; path=/; SameSite=Lax";
  // Also save device mapping to backend
  fetch(WLP.backendUrl + "/api/save-device", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ phone: phone, deviceToken: wlpGetDeviceId(), shop: WLP.shopDomain, wlpToken: wlpToken })
  }).catch(function(){});
}

function wlpGetToken() {
  var match = document.cookie.match(new RegExp("(^| )" + WLP_TOKEN_KEY + "=([^;]+)"));
  return match ? decodeURIComponent(match[2]) : null;
}

function wlpClearSession() {
  document.cookie = WLP_TOKEN_KEY + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
  localStorage.removeItem(WLP_DEVICE_KEY);
}

// Decode token locally (no server needed)
function wlpDecodeToken(token) {
  try {
    if (!token) return null;
    var parts = token.split(".");
    if (parts.length !== 2) return null;
    var payload = JSON.parse(atob(parts[0].replace(/-/g,"+").replace(/_/g,"/")));
    if (payload.exp < Date.now()) { wlpClearSession(); return null; }
    return payload;
  } catch(e) { return null; }
}

// Check if user is logged in via WLP token
function wlpIsLoggedIn() {
  return !!wlpDecodeToken(wlpGetToken());
}

function wlpGetCurrentUser() {
  return wlpDecodeToken(wlpGetToken());
}

// Update header UI to show logged-in state
function wlpUpdateHeaderUI(customer) {
  // Find account icon and update it
  var accountLinks = document.querySelectorAll(".header__icon--account");
  accountLinks.forEach(function(link) {
    link.setAttribute("href", "javascript:void(0)");
    link.setAttribute("onclick", "wlpShowAccountMenu()");
    var label = link.querySelector(".visually-hidden");
    if (label) label.textContent = customer.firstName || "My Account";
  });
  // Show logged-in indicator
  var indicator = document.getElementById("wlp-logged-in-dot");
  if (indicator) indicator.style.display = "block";
}

// Show account menu for logged-in users
function wlpShowAccountMenu() {
  var customer = wlpGetCurrentUser();
  if (!customer) { wlpOpen(); return; }
  // Show mini account panel
  var existing = document.getElementById("wlp-account-menu");
  if (existing) { existing.remove(); return; }
  var menu = document.createElement("div");
  menu.id = "wlp-account-menu";
  menu.style.cssText = "position:fixed;top:70px;right:20px;z-index:999999;background:#fff;border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,0.15);padding:20px;min-width:220px;font-family:inherit;border:1px solid #f0ede8;animation:wlpMenuIn 0.2s ease";
  menu.innerHTML =
    "<style>@keyframes wlpMenuIn{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}</style>" +
    "<div style='font-size:13px;color:#888;margin-bottom:4px'>Logged in as</div>" +
    "<div style='font-size:15px;font-weight:700;color:#1a1714;margin-bottom:2px'>" + (customer.firstName || "") + " " + (customer.lastName || "") + "</div>" +
    "<div style='font-size:12px;color:#b97079;margin-bottom:16px'>" + (customer.phone ? "+91 " + customer.phone : customer.email) + "</div>" +
    "<a href='https://shopify.com/" + WLP.shopDomain.replace(".myshopify.com","").replace(/[^0-9]/g,"").replace("s0xb6fsu","75385176202") + "/account' style='display:block;padding:10px 16px;background:#f5f3ef;border-radius:10px;text-decoration:none;color:#1a1714;font-size:14px;font-weight:600;margin-bottom:8px;text-align:center'>My Orders</a>" +
    "<button onclick='wlpLogout()' style='width:100%;padding:10px 16px;background:none;border:1px solid #e0ddd8;border-radius:10px;color:#888;font-size:14px;cursor:pointer;font-family:inherit'>Logout</button>";
  document.body.appendChild(menu);
  // Close on outside click
  setTimeout(function() {
    document.addEventListener("click", function handler(e) {
      if (!menu.contains(e.target)) { menu.remove(); document.removeEventListener("click", handler); }
    });
  }, 100);
}

function wlpLogout() {
  wlpClearSession();
  var menu = document.getElementById("wlp-account-menu");
  if (menu) menu.remove();
  window.location.reload();
}

// ============================================================
// POPUP OPEN/CLOSE
// ============================================================

function wlpOpen() {
  // If already logged in via WLP token - show account menu instead
  var customer = wlpGetCurrentUser();
  if (customer) { wlpShowAccountMenu(); return; }

  document.getElementById("wlp-overlay").classList.add("wlp-open");
  document.body.style.overflow = "hidden";

  var previewEl = document.getElementById("wlpTempEmailPreview");
  if (previewEl) previewEl.textContent = "(your number)@" + WLP.shopDomain.replace(".myshopify.com","") + ".com";

  // Check device memory - GoKwik style
  var deviceId = wlpGetDeviceId();
  fetch(WLP.backendUrl + "/api/check-device", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deviceToken: deviceId, shop: WLP.shopDomain })
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.known && data.wlpToken) {
      // Restore session from device
      wlpSaveSession(data.wlpToken, data.phone);
      var customer2 = wlpDecodeToken(data.wlpToken);
      if (customer2) {
        wlpClose();
        wlpUpdateHeaderUI(customer2);
        wlpShowAccountMenu();
        return;
      }
    }
    if (data.known && data.phone) {
      // Show returning user panel
      wlpShowReturning(data.phone);
    } else {
      // New user
      wlpShow("wlpP1a");
      setTimeout(function() { var el = document.getElementById("wlpPhone"); if (el) el.focus(); }, 350);
    }
  })
  .catch(function() {
    wlpShow("wlpP1a");
    setTimeout(function() { var el = document.getElementById("wlpPhone"); if (el) el.focus(); }, 350);
  });
}

function wlpShowReturning(phone) {
  wlpShow("wlpP1a");
  var panel = document.getElementById("wlpP1a");
  var masked = "+91 " + phone.substring(0,2) + "XXXX" + phone.substring(6);
  panel.innerHTML =
    "<div style='text-align:center;padding:8px 0 16px'>" +
    "<div style='width:56px;height:56px;border-radius:50%;background:rgba(185,112,121,0.12);border:2px solid #b97079;display:flex;align-items:center;justify-content:center;margin:0 auto 14px;font-size:22px'>&#128075;</div>" +
    "<div class='wlp-title'>Welcome back!</div>" +
    "<div class='wlp-sub' style='margin-bottom:20px'>" + masked + " is saved on this device</div>" +
    "<button class='wlp-btn' onclick='wlpContinueReturning("" + phone + "")' style='margin-bottom:12px'>" +
    "<span>Continue as " + masked + "</span>" +
    "</button>" +
    "<div style='text-align:center;margin-top:12px'>" +
    "<a onclick='wlpUseNewPhone()' style='font-size:13px;color:var(--wlp-brand);cursor:pointer;border-bottom:1px dashed var(--wlp-brand)'>Use a different number</a>" +
    "</div></div>";
}

function wlpContinueReturning(phone) {
  // Send OTP to confirm identity (security best practice)
  wlpState.phone = phone;
  document.getElementById("wlpP1a").innerHTML =
    "<div class='wlp-title'>Enter your mobile</div>" +
    "<div class='wlp-sub'>We'll send a <strong>6-digit OTP</strong> to verify</div>" +
    "<div style='background:rgba(185,112,121,0.08);border:1px solid rgba(185,112,121,0.2);border-radius:12px;padding:14px 16px;margin-bottom:16px;text-align:center;font-size:14px;color:#b97079;font-weight:600'>+91 " + phone.substring(0,2) + "XXXX" + phone.substring(6) + "</div>" +
    "<button class='wlp-btn' id='wlpSendBtn' onclick='wlpSendOtpForPhone("" + phone + "")'>" +
    "<div class='wlp-bspin' id='wlpSendSpin'></div><span id='wlpSendTxt'>Send OTP</span>" +
    "</button>" +
    "<div style='text-align:center;margin-top:12px'>" +
    "<a onclick='wlpUseNewPhone()' style='font-size:13px;color:var(--wlp-muted);cursor:pointer'>Use different number</a>" +
    "</div>";
  wlpSendOtpForPhone(phone);
}

function wlpSendOtpForPhone(phone) {
  wlpState.phone = phone;
  var btn = document.getElementById("wlpSendBtn");
  var spin = document.getElementById("wlpSendSpin");
  var txt = document.getElementById("wlpSendTxt");
  if (btn) btn.disabled = true;
  if (spin) spin.style.display = "block";
  if (txt) txt.textContent = "Sending...";
  fetch(WLP.backendUrl + "/api/send-otp", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({phone:phone,shop:WLP.shopDomain}) })
  .then(function(r){return r.json();})
  .then(function(data){
    if (btn) btn.disabled = false;
    if (spin) spin.style.display = "none";
    if (txt) txt.textContent = "Send OTP";
    if (data.success) {
      document.getElementById("wlpPhoneShow").textContent = "+91 " + phone;
      wlpShow("wlpP1b"); document.querySelectorAll(".wlp-otp-box")[0].focus(); wlpStartTimer(30);
    }
  }).catch(function(){if(btn)btn.disabled=false;});
}

function wlpUseNewPhone() {
  wlpClearSession();
  fetch(WLP.backendUrl + "/api/save-device", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({phone:"",deviceToken:wlpGetDeviceId(),shop:WLP.shopDomain,wlpToken:""}) }).catch(function(){});
  localStorage.removeItem(WLP_DEVICE_KEY);
  wlpShow("wlpP1a");
  document.getElementById("wlpP1a").innerHTML = originalP1aHTML;
  setTimeout(function() { var el = document.getElementById("wlpPhone"); if (el) { el.value=""; el.focus(); } }, 100);
}

function wlpClose() {
  document.getElementById("wlp-overlay").classList.remove("wlp-open");
  document.body.style.overflow = "";
  clearInterval(wlpState.timerInt);
}
function wlpOverlayClick(e) { if (e.target === document.getElementById("wlp-overlay")) wlpClose(); }
document.addEventListener("keydown", function(e) { if (e.key === "Escape") wlpClose(); });

// ============================================================
// STEP INDICATOR
// ============================================================
function wlpSetStep(n) {
  for (var i=1;i<=3;i++) {
    var dot=document.getElementById("wlpDot"+i); var lbl=document.getElementById("wlpLbl"+i); var line=document.getElementById("wlpLine"+i);
    if(dot){dot.className="wlp-step-dot"+(i<n?" done":i===n?" active":"");dot.textContent=i<n?"&#10003;":i;}
    if(lbl){lbl.style.color=i<n?"var(--wlp-ok)":i===n?"var(--wlp-brand)":"var(--wlp-muted)";}
    if(line){line.style.background=i<n?"var(--wlp-ok)":"var(--wlp-border)";}
  }
}
function wlpShow(id) { document.querySelectorAll(".wlp-panel").forEach(function(p){p.classList.remove("active");}); document.getElementById(id).classList.add("active"); }
function wlpGoBack(c,t){wlpShow(t);}

// ============================================================
// OTP BOXES
// ============================================================
(function(){
  var boxes=document.querySelectorAll(".wlp-otp-box");
  boxes.forEach(function(box,i){
    box.addEventListener("input",function(e){
      var v=e.target.value.replace(/\D/g,"");e.target.value=v?v[0]:"";e.target.classList.toggle("wlp-filled",!!v);
      if(v&&i<boxes.length-1)boxes[i+1].focus();
      var otp=Array.from(boxes).map(function(b){return b.value;}).join("");
      if(otp.length===6)wlpVerify();
    });
    box.addEventListener("keydown",function(e){if(e.key==="Backspace"&&!e.target.value&&i>0){boxes[i-1].value="";boxes[i-1].classList.remove("wlp-filled");boxes[i-1].focus();}});
    box.addEventListener("paste",function(e){
      e.preventDefault();
      var paste=(e.clipboardData||window.clipboardData).getData("text").replace(/\D/g,"");
      boxes.forEach(function(b,j){b.value=paste[j]||"";b.classList.toggle("wlp-filled",!!paste[j]);});
      if(paste.length>=6)wlpVerify();else boxes[Math.min(paste.length,5)].focus();
    });
  });
})();

// ============================================================
// SEND OTP
// ============================================================
function wlpSendOtp() {
  var phone=document.getElementById("wlpPhone").value.trim();
  var errEl=document.getElementById("wlpPhoneErr");
  var btn=document.getElementById("wlpSendBtn");
  var spin=document.getElementById("wlpSendSpin");
  var txt=document.getElementById("wlpSendTxt");
  if(!/^\d{10}$/.test(phone)){document.getElementById("wlpPhone").classList.add("wlp-err");errEl.classList.add("show");return;}
  document.getElementById("wlpPhone").classList.remove("wlp-err");errEl.classList.remove("show");
  wlpState.phone=phone;btn.disabled=true;spin.style.display="block";txt.textContent="Sending...";
  fetch(WLP.backendUrl+"/api/send-otp",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({phone:phone,shop:WLP.shopDomain})})
  .then(function(r){return r.json();})
  .then(function(data){
    btn.disabled=false;spin.style.display="none";txt.textContent="Send OTP";
    if(data.success){
      document.getElementById("wlpPhoneShow").textContent="+91 "+phone;
      var pe=document.getElementById("wlpTempEmailPreview");if(pe)pe.textContent=phone+"@"+WLP.shopDomain.replace(".myshopify.com","")+".com";
      wlpShow("wlpP1b");document.querySelectorAll(".wlp-otp-box")[0].focus();wlpStartTimer(30);
    }else{errEl.textContent=data.message||"Failed.";errEl.classList.add("show");}
  }).catch(function(){btn.disabled=false;spin.style.display="none";txt.textContent="Send OTP";errEl.textContent="Network error.";errEl.classList.add("show");});
}

function wlpStartTimer(sec){
  var rb=document.getElementById("wlpResendBtn");var te=document.getElementById("wlpTimer");
  var left=sec;rb.disabled=true;te.textContent=left;clearInterval(wlpState.timerInt);
  wlpState.timerInt=setInterval(function(){left--;te.textContent=left;if(left<=0){clearInterval(wlpState.timerInt);rb.disabled=false;rb.innerHTML="Resend OTP";}},1000);
}

function wlpResend(){
  document.querySelectorAll(".wlp-otp-box").forEach(function(b){b.value="";b.classList.remove("wlp-filled","wlp-err");});
  document.getElementById("wlpOtpErr").classList.remove("show");
  wlpState.phone=document.getElementById("wlpPhone").value.trim();
  fetch(WLP.backendUrl+"/api/send-otp",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({phone:wlpState.phone,shop:WLP.shopDomain})})
  .then(function(){wlpStartTimer(30);}).catch(function(){});
}

// ============================================================
// VERIFY OTP - Core GoKwik-style logic
// ============================================================
function wlpVerify(){
  var boxes=document.querySelectorAll(".wlp-otp-box");
  var otp=Array.from(boxes).map(function(b){return b.value;}).join("");
  var errEl=document.getElementById("wlpOtpErr");
  var btn=document.getElementById("wlpVerifyBtn");
  var spin=document.getElementById("wlpVerifySpin");
  var txt=document.getElementById("wlpVerifyTxt");
  if(otp.length<6)return;
  btn.disabled=true;spin.style.display="block";txt.textContent="Verifying...";
  fetch(WLP.backendUrl+"/api/verify-otp",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({phone:wlpState.phone,otp:otp})})
  .then(function(r){return r.json();})
  .then(function(data){
    btn.disabled=false;spin.style.display="none";txt.textContent="Verify OTP";
    if(data.success){
      errEl.classList.remove("show");clearInterval(wlpState.timerInt);

      if(data.isExistingUser && data.wlpToken){
        // GoKwik-style: save token, update UI, done!
        wlpSaveSession(data.wlpToken, wlpState.phone);
        var customer=wlpDecodeToken(data.wlpToken);
        wlpSetStep(4);
        var sEl=document.getElementById("wlpSuccess");
        sEl.querySelector("h3").textContent="You're logged in!";
        sEl.querySelector("p").innerHTML="Welcome back, <strong>"+(customer?customer.firstName:"")+"</strong>!<br>Your session is saved on this device.";
        wlpShow("wlpSuccess");
        setTimeout(function(){
          wlpClose();
          wlpUpdateHeaderUI(customer);
        },1500);
        return;
      }

      if(data.isExistingUser && !data.wlpToken){
        // Fallback: go to profile to collect data
        wlpSetStep(2);wlpShow("wlpP2");document.getElementById("wlpFirst").focus();
        return;
      }

      // New user - collect profile
      wlpSetStep(2);wlpShow("wlpP2");document.getElementById("wlpFirst").focus();
    }else{
      errEl.textContent=data.message||"Incorrect OTP.";errEl.classList.add("show");
      boxes.forEach(function(b){b.classList.add("wlp-err");});
      setTimeout(function(){boxes.forEach(function(b){b.classList.remove("wlp-err");b.value="";b.classList.remove("wlp-filled");});boxes[0].focus();},700);
    }
  }).catch(function(){btn.disabled=false;spin.style.display="none";txt.textContent="Verify OTP";errEl.textContent="Network error.";errEl.classList.add("show");});
}

// ============================================================
// PROFILE STEP
// ============================================================
function wlpNextToEmail(){
  var ok=true;
  function req(id,errId,testFn){var el=document.getElementById(id);var er=document.getElementById(errId);var v=testFn(el.value.trim());el.classList.toggle("wlp-err",!v);er.classList.toggle("show",!v);if(!v)ok=false;}
  req("wlpFirst","wlpFirstErr",function(v){return v.length>0;});
  req("wlpAddr1","wlpAddr1Err",function(v){return v.length>3;});
  req("wlpCity","wlpCityErr",function(v){return v.length>1;});
  req("wlpPin","wlpPinErr",function(v){return /^\d{6}$/.test(v);});
  req("wlpState","wlpStateErr",function(v){return v!="";});
  if(!ok)return;
  wlpSetStep(3);wlpShow("wlpP3");document.getElementById("wlpEmail").focus();
}

// ============================================================
// FINAL SUBMIT - Create customer + save WLP session
// ============================================================
function wlpSubmit(skip){
  var email=document.getElementById("wlpEmail").value.trim();
  var errEl=document.getElementById("wlpEmailErr");
  var btn=document.getElementById("wlpSubmitBtn");
  var spin=document.getElementById("wlpSubmitSpin");
  var txt=document.getElementById("wlpSubmitTxt");
  if(!skip&&email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){document.getElementById("wlpEmail").classList.add("wlp-err");errEl.classList.add("show");return;}
  errEl.classList.remove("show");document.getElementById("wlpEmail").classList.remove("wlp-err");
  btn.disabled=true;spin.style.display="block";txt.textContent="Creating account...";
  var payload={phone:wlpState.phone,firstName:document.getElementById("wlpFirst").value.trim(),lastName:document.getElementById("wlpLast").value.trim(),address1:document.getElementById("wlpAddr1").value.trim(),address2:document.getElementById("wlpAddr2").value.trim(),city:document.getElementById("wlpCity").value.trim(),pincode:document.getElementById("wlpPin").value.trim(),state:document.getElementById("wlpState").value,country:"India",email:skip?"":email,shop:WLP.shopDomain};
  fetch(WLP.backendUrl+"/api/create-customer",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)})
  .then(function(r){return r.json();})
  .then(function(data){
    btn.disabled=false;spin.style.display="none";txt.textContent="Complete Login";
    if(data.success&&data.wlpToken){
      // GoKwik-style: save session, done!
      wlpSaveSession(data.wlpToken, wlpState.phone);
      var customer=wlpDecodeToken(data.wlpToken);
      wlpSetStep(4);
      var sEl=document.getElementById("wlpSuccess");
      sEl.querySelector("h3").textContent="You're logged in!";
      sEl.querySelector("p").innerHTML="Welcome, <strong>"+(customer?customer.firstName:"")+"</strong>!<br>Your account is ready.";
      if(data.customer.isTemp){document.getElementById("wlpTempEmailFinal").textContent=data.customer.tempEmail;document.getElementById("wlpTempNotice").style.display="block";}
      wlpShow("wlpSuccess");
      setTimeout(function(){wlpClose();wlpUpdateHeaderUI(customer);},1500);
    }else{
      var errDiv=document.createElement("div");errDiv.style.cssText="color:#dc2626;font-size:13px;margin-top:10px;text-align:center";errDiv.textContent=data.message||"Something went wrong.";btn.parentNode.appendChild(errDiv);setTimeout(function(){errDiv.remove();},4000);
    }
  }).catch(function(){btn.disabled=false;spin.style.display="none";txt.textContent="Complete Login";});
}

// ============================================================
// INIT - Check session on page load
// ============================================================
var originalP1aHTML = "";

document.addEventListener("DOMContentLoaded", function() {
  // Save original panel HTML for reset
  var p1a = document.getElementById("wlpP1a");
  if (p1a) originalP1aHTML = p1a.innerHTML;

  // Check if already logged in via WLP token
  var customer = wlpGetCurrentUser();
  if (customer) {
    wlpUpdateHeaderUI(customer);
  }

  if (!wlp_customer_logged_in) {
  // Intercept login links
  function interceptLink(el) {
    el.addEventListener("click", function(e) { e.preventDefault(); e.stopPropagation(); wlpOpen(); });
  }
  document.querySelectorAll("a[href*='authentication'], a[href='/account/login'], a[href='/account']").forEach(interceptLink);
  var obs=new MutationObserver(function(muts){muts.forEach(function(m){m.addedNodes.forEach(function(node){if(node.nodeType===1){var links=node.querySelectorAll?node.querySelectorAll("a"):[];links.forEach(function(el){var h=el.getAttribute("href")||"";if(h.includes("/authentication/")||h.includes("/account/login")||h==="/account")interceptLink(el);});}});});});
  obs.observe(document.body,{childList:true,subtree:true});
  } // end unless customer
});

if (!wlp_customer_logged_in)
document.addEventListener("click",function(e){
  var el=e.target.closest("a");if(!el)return;
  var href=el.getAttribute("href")||"";
  if(href.includes("/authentication/")||href.includes("/account/login")||href==="/account"){e.preventDefault();e.stopPropagation();wlpOpen();}
},true);


// Expose globally
window.wlpOpen=wlpOpen;window.wlpClose=wlpClose;window.wlpSendOtp=wlpSendOtp;
window.wlpResend=wlpResend;window.wlpVerify=wlpVerify;window.wlpNextToEmail=wlpNextToEmail;
window.wlpSubmit=wlpSubmit;window.wlpGoBack=wlpGoBack;window.wlpOverlayClick=wlpOverlayClick;
window.wlpShowAccountMenu=wlpShowAccountMenu;window.wlpLogout=wlpLogout;
window.wlpContinueReturning=wlpContinueReturning;window.wlpUseNewPhone=wlpUseNewPhone;

})();
