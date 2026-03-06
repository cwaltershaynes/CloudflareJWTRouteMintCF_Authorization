# HaynesConnect JWT Gate

Cloudflare Worker used to protect HaynesConnect subdomains.

Authentication flow:

User → haynesconnect.com login → Cognito  
↓  
JWT cookie `hc_session` issued for `.haynesconnect.com`  
↓  
Worker validates JWT  
↓  
Access allowed to site subdomain

Example protected hosts:

siteA.haynesconnect.com  
siteB.haynesconnect.com  
compass.customer1.haynesconnect.com

## Deploy

Install dependencies

npm install

Deploy worker

npm run deploy

## Local dev

wrangler dev
