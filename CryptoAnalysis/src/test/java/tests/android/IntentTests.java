package tests.android;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import org.junit.Test;
import test.UsagePatternTestingFramework;

public class IntentTests extends UsagePatternTestingFramework {
    @Test
    public void initialIntentTest(){
        Intent intent = new Intent();
        Activity context = new Activity();
        context.setIntent(intent);
    }
}
