# Veilmark

**Product name:** Veilmark
**Descriptor:** Local text redaction

The name pairs concealment with the mark left by redaction. The logo combines a white document, navy redaction bars and a teal masking bar. Its bold silhouette is intended for small Windows icons as well as the app header.

## Assets and application

- `Veilmark.png`: original high-resolution generated logo with transparent exterior.
- `Veilmark.ico`: Windows icon containing 16, 20, 24, 32, 40, 48, 64, 128 and 256-pixel versions.
- `Veilmark.exe`: embeds both assets; no adjacent image files are required to run it. The ICO is compiled into the executable's Windows icon resource and used as its window/taskbar icon. The full logo appears beside the product name in the app.
- `Build-Icon.ps1`: rebuilds the ICO sizes from the logo with alpha-preserving resampling. `Build.ps1` rebuilds the executable from the supplied source and assets.

The starting palette is deep navy `#142B43`, teal `#21C7B7` and white. The supplied raster artwork may contain slight tonal variation. The name is a creative product name; trademark and domain availability have not been checked.

## Generation provenance

Generated using the built-in image-generation tool, followed by Windows ICO format conversion. The logo design was not otherwise altered.

### Final generation prompt

Use case: logo-brand. Asset type: production logo symbol for Veilmark, a professional Windows app that redacts sensitive text locally. Create ONE finished square app icon, not a mockup or presentation. A confident minimal white document silhouette, with a subtly clipped upper-right corner, inside a deep navy rounded-square tile. Two thick navy horizontal redaction bars inside the page, and a single bold teal horizontal redaction bar extending a little beyond the page's right edge. Elegant balanced flat geometric design, generous clear shapes that remain legible at 16px. Palette navy #142B43, teal #21C7B7, white #FFFFFF. Center the tile and let it fill about 90% of the canvas with a small even outside margin. Exterior canvas must be genuinely transparent; preserve alpha. Crisp straight edges, restrained corner rounding. No lettering, no wordmark, no tiny detail, no shield, no lock, no gradients, no shadows, no texture, no 3D, no watermark. Deliver a single high-resolution square logo icon.
