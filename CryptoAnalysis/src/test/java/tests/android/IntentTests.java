package tests.android;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import crypto.analysis.Constants;
import org.junit.Test;
import test.UsagePatternTestingFramework;

public class IntentTests extends UsagePatternTestingFramework {
    @Test
    public void initialIntentTest(){
        Intent intent = new Intent();
        Activity context = new Activity();
        context.setIntent(intent);
        context.startActivity(intent);
    }

    @Test
    public void methodTests(){
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.putExtra("name", 0);
        intent.putExtras(intent);
        intent.setClassName("packagename", "className");
    }

    @Test
    public void multipleParamsConstr(){
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(""));
        intent.setData(Uri.parse(""));
    }

    @Override
    protected Constants.Ruleset getRuleSet() {
        return Constants.Ruleset.JavaCryptographicArchitecture;
    }
}
