# VELA Desktop Icons

This directory contains application icons for VELA Desktop.

## Icon Files Required

For the application to build, you need to provide the following icon files:

### Windows
- `icon.ico` - Windows icon file (multi-resolution)
- `32x32.png` - 32x32 PNG icon
- `128x128.png` - 128x128 PNG icon  
- `128x128@2x.png` - 256x256 PNG icon (high DPI)

### macOS
- `icon.icns` - macOS icon file

## Generating Icons

You can use the `icon.svg` file as a source to generate all required icon formats.

### Using tauricon (recommended)
```bash
npm install -g @aspect-build/tauricon
tauricon -s icons/icon.svg -o icons/
```

### Using ImageMagick
```bash
# For Windows
magick convert -background none icon.svg -define icon:auto-resize="256,128,64,48,32,16" icon.ico
magick convert -background none icon.svg -resize 32x32 32x32.png
magick convert -background none icon.svg -resize 128x128 128x128.png
magick convert -background none icon.svg -resize 256x256 128x128@2x.png

# For macOS
magick convert -background none icon.svg icon.icns
```

### Online Converters
You can also use online tools like:
- https://cloudconvert.com/svg-to-ico
- https://cloudconvert.com/svg-to-png
- https://cloudconvert.com/png-to-icns
