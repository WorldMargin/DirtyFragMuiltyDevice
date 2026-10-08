package com.worldmargin.dfroot;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.View;

/**
 * OneUI-style bottom fade. Draws a LinearGradient with explicit positions
 * so the curve can be aggressive (steep late falloff) while still starting
 * at fully transparent - no visible seam at the top edge.
 */
public class BottomFadeView extends View {

    private final Paint paint = new Paint();

    // Fade curve: transparent -> 40% at 32% -> 90% at 60% -> solid from 82%.
    private static final int[] COLORS = {
            0x00000000,
            0x66000000,
            0xE6000000,
            0xFF000000,
            0xFF000000
    };
    private static final float[] POSITIONS = {0f, 0.32f, 0.60f, 0.82f, 1f};

    public BottomFadeView(Context context) {
        super(context);
    }

    public BottomFadeView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public BottomFadeView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    @Override
    protected void onSizeChanged(int w, int h, int oldW, int oldH) {
        super.onSizeChanged(w, h, oldW, oldH);
        paint.setShader(new LinearGradient(0, 0, 0, h, COLORS, POSITIONS, Shader.TileMode.CLAMP));
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        canvas.drawRect(0, 0, getWidth(), getHeight(), paint);
    }
}
