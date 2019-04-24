package tests.android;

import android.app.Activity;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import crypto.analysis.Constants;
import org.junit.Test;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class LinearLayoutTests  extends UsagePatternTestingFramework {

    @Test
    public void linearLayoutAddViewTest(){
        Activity context = new Activity();
        LinearLayout layout = new LinearLayout(context);
        Assertions.extValue(0);
        Button button = new Button(context);
        Assertions.extValue(0);
        layout.addView(button);

    }
    @Test
    public void linearLayoutAddViewTest2(){
        Activity context = new Activity();
        LinearLayout layout = new LinearLayout(context);
        Assertions.extValue(0);
        Button button = new Button(context);
        Assertions.extValue(0);
        int position = 40;
        layout.addView(button, position);
        Assertions.extValue(0);
        Assertions.extValue(1);
    }

    @Test
    public void linearLayoutAddViewTest3(){
        Activity context = new Activity();
        LinearLayout layout = new LinearLayout(context);
        Assertions.extValue(0);
        Button button = new Button(context);
        Assertions.extValue(0);
        int width = 200;
        int height = 300;
        layout.addView(button, width, height);
        Assertions.extValue(0);
        Assertions.extValue(1);
        Assertions.extValue(2);
    }

    @Test
    public void linearLayoutSetCustomResId(){
        Activity context = new Activity();
        LinearLayout layout = new LinearLayout(context);
        Assertions.extValue(0);
        int customResId = 500;
        layout.setId(customResId);
        Assertions.extValue(0);
    }

    @Test
    public void linearLayoutListeners(){
        Activity context = new Activity();
        LinearLayout layout = new LinearLayout(context);
        Assertions.extValue(0);
        layout.setOnClickListener((View view) -> {});
        Assertions.extValue(0);
        layout.setOnFocusChangeListener((View view, boolean b) -> {});
        Assertions.extValue(0);
        layout.setOnKeyListener((View view, int i, KeyEvent keyEvent) -> false);
        Assertions.extValue(0);
        layout.setOnTouchListener((View view, MotionEvent motionEvent) -> false);
        Assertions.extValue(0);
    }

    @Override
    protected Constants.Ruleset getRuleSet() {
        return Constants.Ruleset.JavaCryptographicArchitecture;
    }
}
