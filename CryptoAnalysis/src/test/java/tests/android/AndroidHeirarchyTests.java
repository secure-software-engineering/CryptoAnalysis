package tests.android;

import android.app.Activity;
import android.content.Context;
import android.widget.Button;
import android.widget.LinearLayout;
import org.junit.Test;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

import java.util.Random;

public class AndroidHeirarchyTests extends UsagePatternTestingFramework {

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

        layout.addView(button1);
        Assertions.extValue(0);

        context.setContentView(layout);
        Assertions.extValue(0);
    }

    @Test
    public void multipleActivitesUsed(){
        Activity context = new Activity();

        LinearLayout layout = new LinearLayout(context);
        Assertions.extValue(0);
        Button button1 = new Button(context);
        Assertions.extValue(0);
        String name = "rajiv";
        button1.setText(name);
        Assertions.extValue(0);

        layout.addView(button1);
        Assertions.extValue(0);

        context.setContentView(layout);
        Assertions.extValue(0);

        Activity duplicateContext = new Activity();
        LinearLayout duplicateLayout = new LinearLayout(duplicateContext);
        Assertions.extValue(0);
        Button duplicateButton = new Button(duplicateContext);
        Assertions.extValue(0);
        String duplicateName = "thorat";
        duplicateButton.setText(duplicateName);
        Assertions.extValue(0);
        //button1.setId(20);

        duplicateLayout.addView(duplicateButton);
        Assertions.extValue(0);

        duplicateContext.setContentView(duplicateLayout);
        Assertions.extValue(0);
    }

    @Test
    public void multipleActivitiesUnused(){
        Activity context = new Activity();
        Activity duplicateContext = new Activity();
        LinearLayout layout = new LinearLayout(context);
        LinearLayout duplicateLayout = new LinearLayout(null);
        Assertions.extValue(0);
        Button button1 = new Button(context);
        Button duplicateButton = new Button(null);
        Assertions.extValue(0);
        String name = "rajiv";
        button1.setText(name);
        Assertions.extValue(0);

        layout.addView(button1);
        Assertions.extValue(0);

        context.setContentView(layout);
        Assertions.extValue(0);
    }

    @Test
    public void customActivity(){
        CustomActivity context = new CustomActivity();
        LinearLayout layout = new LinearLayout(context);
        Assertions.extValue(0);
        Button button1 = new Button(context);
        Assertions.extValue(0);
        String name = "rajiv";
        button1.setText(name);
        Assertions.extValue(0);

        layout.addView(button1);
        Assertions.extValue(0);

        context.setContentView(layout);
        Assertions.extValue(0);
    }

    protected class CustomActivity extends Activity{

     }

     @Test
    public void customLayout(){
         Activity context = new Activity();
         CustomLayout layout = new CustomLayout(context);
         Assertions.extValue(0);
         Button button1 = new Button(context);
         Assertions.extValue(0);
         String name = "rajiv";
         button1.setText(name);
         Assertions.extValue(0);

         layout.addView(button1);
         Assertions.extValue(0);

         context.setContentView(layout);
         Assertions.extValue(0);
     }

     protected class CustomLayout extends LinearLayout{

         public CustomLayout(Context context) {
             super(context);
         }
     }

     @Test
    public void customButton(){
         Activity context = new Activity();
         LinearLayout layout = new LinearLayout(context);
         Assertions.extValue(0);
         CustomButton button1 = new CustomButton(context);
         Assertions.extValue(0);
         String name = "rajiv";
         button1.setText(name);
         Assertions.extValue(0);

         layout.addView(button1);
         Assertions.extValue(0);

         context.setContentView(layout);
         Assertions.extValue(0);
     }

     protected class CustomButton extends Button{

         public CustomButton(Context context) {
             super(context);
         }
     }

     @Test
     public void allCustom(){
         CustomActivity context = new CustomActivity();
         CustomLayout layout = new CustomLayout(context);
         Assertions.extValue(0);
         CustomButton button1 = new CustomButton(context);
         Assertions.extValue(0);
         String name = "rajiv";
         button1.setText(name);
         Assertions.extValue(0);

         layout.addView(button1);
         Assertions.extValue(0);

         context.setContentView(layout);
         Assertions.extValue(0);
     }

     @Test
    public void layoutInDifferentMethod(){
         Activity context = new Activity();
         LinearLayout layout = addLayout(context);
         Assertions.extValue(0);
         Button button1 = new Button(context);
         Assertions.extValue(0);
         String name = "rajiv";
         button1.setText(name);
         Assertions.extValue(0);

         layout.addView(button1);
         Assertions.extValue(0);

         context.setContentView(layout);
         Assertions.extValue(0);
     }

     private LinearLayout addLayout(Activity context){
         return new LinearLayout(context);

     }

     @Test
     public void buttonInDifferentMethod(){
         Activity context = new Activity();
         LinearLayout layout = new LinearLayout(context);
         Assertions.extValue(0);
         Button button1 = addButton(context);
         Assertions.extValue(0);
         String name = "rajiv";
         button1.setText(name);
         Assertions.extValue(0);

         layout.addView(button1);
         Assertions.extValue(0);

         context.setContentView(layout);
         Assertions.extValue(0);
     }

     private Button addButton(Activity context){
         return new Button(context);

     }
     @Test
    public void conditionalLayout(){
         Activity context = new Activity();

         Random rand = new Random();

         LinearLayout layout;

         if((rand.nextInt(50) + 1) % 2 == 1){
             layout = addLayout(context);
         } else {
             layout = new LinearLayout(context);
         }


         Assertions.extValue(0);
         Button button1 = new Button(context);
         Assertions.extValue(0);
         String name = "rajiv";
         button1.setText(name);
         Assertions.extValue(0);

         layout.addView(button1);
         Assertions.extValue(0);

         context.setContentView(layout);
         Assertions.extValue(0);
     }

     @Test
    public void conditionalButton(){
         Activity context = new Activity();
         LinearLayout layout = new LinearLayout(context);
         Assertions.extValue(0);

         Button button1;

         Random rand = new Random();
         if((rand.nextInt(50) + 1) % 2 == 1){
             button1 = addButton(context);
         } else {
             button1 = new Button(context);
         }



         Assertions.extValue(0);
         String name = "rajiv";
         button1.setText(name);
         Assertions.extValue(0);

         layout.addView(button1);
         Assertions.extValue(0);

         context.setContentView(layout);
         Assertions.extValue(0);
     }


    @Test
    public void switchedButton(){
        Activity context = new Activity();
        LinearLayout layout = new LinearLayout(context);
        Assertions.extValue(0);
        Button button1 = new Button(context);
        Assertions.extValue(0);
        String name = "rajiv";
        button1.setText(name);
        Assertions.extValue(0);

        layout.addView(button1);
        Assertions.extValue(0);

        context.setContentView(layout);
        Assertions.extValue(0);

        Activity context2 = new Activity();
        LinearLayout layout2 = new LinearLayout(context2);
        Assertions.extValue(0);
        button1 = new Button(context2); // This one does not seem to register in the tests.
        Assertions.extValue(0);
        String name2 = "thorat";
        button1.setText(name2);
        Assertions.extValue(0);

        layout2.addView(button1);
        Assertions.extValue(0);

        context2.setContentView(layout2);
        Assertions.extValue(0);
    }
}
