# Nexplay Proxy

A Render-ready Node.js web launcher with a custom Nexplay interface.

## Deploy to Render

1. Create a GitHub repository and upload these files to its root.
2. In Render, choose **New + → Web Service** and connect the repository.
3. Use:
   - Runtime: Node
   - Build command: `npm install`
   - Start command: `npm start`
4. Deploy. Render will provide an HTTPS URL.

## Google Sites embed

After deployment, replace `YOUR-RENDER-URL` with the Render URL and paste this into Google Sites → Insert → Embed → Embed code:

```html
<iframe
  src="https://YOUR-RENDER-URL"
  title="Nexplay Proxy"
  style="width:100%;height:750px;border:0;border-radius:14px"
  loading="lazy"
  allow="fullscreen">
</iframe>
```

## Notes

This starter is a branded web launcher, not a traffic-relaying proxy. It opens destinations in a new tab and does not circumvent network restrictions, authentication, or website security controls. Some websites do not permit iframe embedding.
