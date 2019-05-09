package tests.android;

import android.app.Activity;
import android.content.Intent;
import android.widget.LinearLayout;
import crypto.analysis.CrySLRulesetSelector;
import org.junit.Test;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;


public class ActivityTests  extends UsagePatternTestingFramework {

    @Test
    public void activityTitleTest(){
        Activity context = new Activity();
        int titleResId = 10;
        context.setTitle(titleResId);
        Assertions.extValue(0);
    }

    @Test
    public void activityTitleTest2(){
        Activity context = new Activity();
        String title = "rajiv";
        context.setTitle(title);
        Assertions.extValue(0);
    }

    @Test
    public void activityContentViewTest(){
        Activity context = new Activity();
        LinearLayout layout = new LinearLayout(context);
        context.setContentView(layout);
        Assertions.extValue(0);
    }

    @Test
    public void activityContextViewTest2(){
        Activity context = new Activity();
        int layoutResId = 20;
        context.setContentView(layoutResId);
        Assertions.extValue(0);
    }

    @Test
    public void activityFindViewByIdTest(){
        Activity context = new Activity();
        int viewResId = 30;
        context.findViewById(viewResId);
        Assertions.extValue(0);
    }

    @Test
    public void activityTest(){
        Activity context = new Activity();
        Intent intent = new Intent();
        context.setIntent(intent);
        Assertions.extValue(0);
    }

    @Override
    protected CrySLRulesetSelector.Ruleset getRuleSet() {
        return CrySLRulesetSelector.Ruleset.JavaCryptographicArchitecture;
    }
}
