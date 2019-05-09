package tests.android;

import android.app.Activity;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import crypto.analysis.CrySLRulesetSelector;
import org.junit.Test;
import test.UIExtractionFrameworkBasedOnUPTF;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class ButtonTests extends UsagePatternTestingFramework {

    @Test
    public void buttonTest(){
        Activity context = new Activity();
        LinearLayout layout = new LinearLayout(context);
        Assertions.extValue(0);
        Button button1 = new Button(context);
        Assertions.extValue(0);
        String name = "rajiv";
        button1.setText(name);
        Assertions.extValue(0);
        //button1.setId(20);

        layout.addView(button1);
        Assertions.extValue(0);

        context.setContentView(layout);
        Assertions.extValue(0);
    }

    @Test
    public void buttonRidTest(){
        Activity context = new Activity();
        Button button = new Button(context);
        Assertions.extValue(0);
        int customResId = 1000;
        button.setId(customResId);
        Assertions.extValue(0);
    }

    @Test
    public void buttonSetText(){
        Activity context = new Activity();
        Button button = new Button(context);
        Assertions.extValue(0);
        int textResID = 1001;
        button.setText(textResID);
        Assertions.extValue(0);
    }

    @Test
    public void buttonSetText2(){
        Activity context = new Activity();
        Button button = new Button(context);
        Assertions.extValue(0);
        String text = "button test rajiv";
        button.setText(text);
        Assertions.extValue(0);
    }

    @Test
    public void buttonSetText3(){
        Activity context = new Activity();
        Button button = new Button(context);
        Assertions.extValue(0);
        String text = "button test rajiv";
        int begin = 0;
        int end = 5;
        button.setText(text.toCharArray(), begin, end);
        Assertions.extValue(0);
        Assertions.extValue(1);
        Assertions.extValue(2);
    }

    @Test
    public void buttonListeners(){
        Activity context = new Activity();
        Button button = new Button(context);
        Assertions.extValue(0);

        button.setOnClickListener((View view) -> {});
        Assertions.extValue(0);
        button.setOnFocusChangeListener((View view, boolean b) -> {});
        Assertions.extValue(0);
        button.setOnKeyListener((View view, int i, KeyEvent keyEvent) -> false);
        Assertions.extValue(0);
        button.setOnTouchListener((View view, MotionEvent motionEvent) -> false);
        Assertions.extValue(0);
    }

    @Test
    public void buttonInherTest(){
        Activity context = new Activity();
        LinearLayout layout = new LinearLayout(context);
        //Assertions.extValue(0);
        Inher_Button button1 = new Inher_Button(context);
        //Assertions.extValue(0);
        String name = "rajiv";
        button1.setText(name);
        Assertions.extValue(0);
        //button1.setId(20);

        layout.addView(button1);
        //Assertions.extValue(0);

        context.setContentView(layout);
        //Assertions.extValue(0);
    }

    @Override
    protected CrySLRulesetSelector.Ruleset getRuleSet() {
        return CrySLRulesetSelector.Ruleset.JavaCryptographicArchitecture;
    }
}
