param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "dist/app.ico"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$source = @'
using System;
using System.IO;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

public static class PrivateVPNIcon
{
    private static PointF P(float x, float y, float scale)
    {
        return new PointF(128f + (x - 128f) * scale, 128f + (y - 128f) * scale);
    }

    private static GraphicsPath RoundedRect(float x, float y, float width, float height, float radius)
    {
        GraphicsPath path = new GraphicsPath();
        float d = radius * 2f;
        path.AddArc(x, y, d, d, 180f, 90f);
        path.AddArc(x + width - d, y, d, d, 270f, 90f);
        path.AddArc(x + width - d, y + height - d, d, d, 0f, 90f);
        path.AddArc(x, y + height - d, d, d, 90f, 90f);
        path.CloseFigure();
        return path;
    }

    private static GraphicsPath Shield(float scale)
    {
        GraphicsPath path = new GraphicsPath();
        path.StartFigure();
        path.AddBezier(P(128, 25, scale), P(154, 38, scale), P(180, 49, scale), P(213, 60, scale));
        path.AddBezier(P(213, 60, scale), P(215, 99, scale), P(215, 136, scale), P(202, 162, scale));
        path.AddBezier(P(202, 162, scale), P(185, 194, scale), P(158, 215, scale), P(128, 231, scale));
        path.AddBezier(P(128, 231, scale), P(98, 215, scale), P(71, 194, scale), P(54, 162, scale));
        path.AddBezier(P(54, 162, scale), P(41, 136, scale), P(41, 99, scale), P(43, 60, scale));
        path.AddBezier(P(43, 60, scale), P(76, 49, scale), P(102, 38, scale), P(128, 25, scale));
        path.CloseFigure();
        return path;
    }

    private static Bitmap Render(int size)
    {
        Bitmap bitmap = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        using (Graphics g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.Clear(Color.Transparent);
            float scale = size / 256f;
            g.ScaleTransform(scale, scale);

            using (GraphicsPath background = RoundedRect(3, 3, 250, 250, 43))
            using (LinearGradientBrush bg = new LinearGradientBrush(
                new Rectangle(0, 0, 256, 256),
                Color.FromArgb(255, 7, 15, 31),
                Color.FromArgb(255, 23, 39, 67),
                45f))
            using (Pen border = new Pen(Color.FromArgb(180, 48, 76, 119), 2f))
            {
                g.FillPath(bg, background);
                g.DrawPath(border, background);
            }

            using (GraphicsPath shadow = Shield(1f))
            using (Matrix shift = new Matrix())
            using (SolidBrush shadowBrush = new SolidBrush(Color.FromArgb(95, 0, 0, 0)))
            {
                shift.Translate(0f, 5f);
                shadow.Transform(shift);
                g.FillPath(shadowBrush, shadow);
            }

            using (GraphicsPath outer = Shield(1f))
            using (LinearGradientBrush green = new LinearGradientBrush(
                new Point(48, 28), new Point(205, 230),
                Color.FromArgb(255, 43, 244, 143),
                Color.FromArgb(255, 0, 133, 78)))
            using (Pen rim = new Pen(Color.FromArgb(210, 126, 255, 190), 2.5f))
            {
                g.FillPath(green, outer);
                g.DrawPath(rim, outer);
            }

            using (GraphicsPath inner = Shield(0.82f))
            using (LinearGradientBrush dark = new LinearGradientBrush(
                new Point(70, 55), new Point(185, 210),
                Color.FromArgb(255, 8, 78, 52),
                Color.FromArgb(255, 5, 48, 40)))
            {
                g.FillPath(dark, inner);
            }

            using (Pen check = new Pen(Color.White, 19f))
            {
                check.StartCap = LineCap.Round;
                check.EndCap = LineCap.Round;
                check.LineJoin = LineJoin.Round;
                g.DrawLines(check, new PointF[] {
                    new PointF(82, 127),
                    new PointF(112, 157),
                    new PointF(174, 94)
                });
            }

        }
        return bitmap;
    }

    public static void Create(string outputPath)
    {
        int[] sizes = new int[] { 16, 24, 32, 48, 64, 128, 256 };
        byte[][] pngs = new byte[sizes.Length][];
        for (int i = 0; i < sizes.Length; i++)
        {
            using (Bitmap bitmap = Render(sizes[i]))
            using (MemoryStream stream = new MemoryStream())
            {
                bitmap.Save(stream, ImageFormat.Png);
                pngs[i] = stream.ToArray();
            }
        }

        string directory = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        Directory.CreateDirectory(directory);
        using (FileStream file = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
        using (BinaryWriter writer = new BinaryWriter(file))
        {
            writer.Write((ushort)0);
            writer.Write((ushort)1);
            writer.Write((ushort)sizes.Length);
            int offset = 6 + 16 * sizes.Length;
            for (int i = 0; i < sizes.Length; i++)
            {
                byte dimension = (byte)(sizes[i] == 256 ? 0 : sizes[i]);
                writer.Write(dimension);
                writer.Write(dimension);
                writer.Write((byte)0);
                writer.Write((byte)0);
                writer.Write((ushort)1);
                writer.Write((ushort)32);
                writer.Write((uint)pngs[i].Length);
                writer.Write((uint)offset);
                offset += pngs[i].Length;
            }
            foreach (byte[] png in pngs)
                writer.Write(png);
        }
    }
}
'@

$assemblyPaths = @(
    [System.Drawing.Bitmap].Assembly.Location,
    [System.Drawing.Color].Assembly.Location,
    [System.Drawing.PointF].Assembly.Location
)
$runtimeDirectory = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
$privateWindowsAssemblies = Get-ChildItem -Path @($PSHOME, $runtimeDirectory) -Filter 'System.Private.Windows.*.dll' -File -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { $_.FullName }
$assemblyPaths += $privateWindowsAssemblies
$assemblyPaths = $assemblyPaths | Where-Object { $_ } | Select-Object -Unique

$gdiFound = $assemblyPaths | Where-Object { [IO.Path]::GetFileName($_) -eq 'System.Private.Windows.GdiPlus.dll' }
$coreFound = $assemblyPaths | Where-Object { [IO.Path]::GetFileName($_) -eq 'System.Private.Windows.Core.dll' }
if (-not $gdiFound) {
    throw 'Could not locate System.Private.Windows.GdiPlus.dll required by System.Drawing.'
}
if (-not $coreFound) {
    throw 'Could not locate System.Private.Windows.Core.dll required by System.Drawing.'
}

Add-Type -TypeDefinition $source -ReferencedAssemblies $assemblyPaths
[PrivateVPNIcon]::Create($OutputPath)

if (-not (Test-Path -LiteralPath $OutputPath)) {
    throw "Icon generation failed: $OutputPath was not created"
}
Write-Host "Generated PrivateVPN Next multi-resolution icon: $OutputPath"
