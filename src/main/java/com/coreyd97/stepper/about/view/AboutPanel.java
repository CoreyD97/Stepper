package com.coreyd97.stepper.about.view;

import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.util.view.NoTextSelectionCaret;
import com.coreyd97.stepper.util.view.WrappedTextPane;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class AboutPanel extends JPanel {


    public AboutPanel(){
        this.setLayout(new GridBagLayout());
        JPanel innerPanel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1;
        gbc.weighty = 0;
        gbc.gridx = gbc.gridy = 1;
        JLabel headerLabel = new JLabel("Stepper");
        Font font = this.getFont().deriveFont(32f).deriveFont(this.getFont().getStyle() | Font.BOLD);
        headerLabel.setFont(font);
        headerLabel.setHorizontalAlignment(SwingConstants.CENTER);
        innerPanel.add(headerLabel, gbc);

        gbc.gridy++;
        gbc.weighty = 0;
        JLabel subtitle = new JLabel("A multi-stage repeater replacement");
        Font subtitleFont = subtitle.getFont().deriveFont(16f).deriveFont(subtitle.getFont().getStyle() | Font.ITALIC);
        subtitle.setFont(subtitleFont);
        subtitle.setHorizontalAlignment(SwingConstants.CENTER);
        innerPanel.add(subtitle, gbc);

        gbc.gridy++;
        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
        separator.setBorder(BorderFactory.createEmptyBorder(7,0,7,0));
        innerPanel.add(separator, gbc);

        JPanel contactPanel = new JPanel(new GridLayout(2,0));

        ImageIcon twitterImage = loadImage("TwitterLogo.png", 30, 30);
        JButton twitterButton;
        if(twitterImage != null){
            twitterButton = new JButton("Follow me on Twitter", twitterImage);
            twitterButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
            twitterButton.setIconTextGap(7);
        }else{
            twitterButton = new JButton("Follow me on Twitter");
        }

        twitterButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI("https://twitter.com/coreyd97"));
            } catch (IOException | URISyntaxException e) {}
        });


        String githubLogoFilename = "GitHubLogo" +
                (UIManager.getLookAndFeel().getName().equalsIgnoreCase("darcula") ? "White" : "Black")
                + ".png";
        ImageIcon githubImage = loadImage(githubLogoFilename, 30, 30);
        JButton viewOnGithubButton;
        if(githubImage != null){
            viewOnGithubButton = new JButton("View Project on GitHub", githubImage);
            viewOnGithubButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
            viewOnGithubButton.setIconTextGap(7);
        }else{
            viewOnGithubButton = new JButton("View Project on GitHub");
        }
        viewOnGithubButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI("https://github.com/CoreyD97/Stepper"));
            } catch (IOException | URISyntaxException e) {}
        });
        contactPanel.add(new JLabel("Created by:"));
        contactPanel.add(twitterButton);
        contactPanel.add(new JLabel("Corey Arthur, @CoreyD97"));
        contactPanel.add(viewOnGithubButton);
        contactPanel.setBorder(BorderFactory.createEmptyBorder(0,10,15,0));

        gbc.gridy++;
        innerPanel.add(contactPanel, gbc);

        gbc.gridy++;
        gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;
        WrappedTextPane aboutContent = new WrappedTextPane();
        aboutContent.setEditable(false);
        aboutContent.setOpaque(false);
        aboutContent.setCaret(new NoTextSelectionCaret(aboutContent));
        JScrollPane aboutScrollPane = new JScrollPane(aboutContent);
        aboutScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        aboutScrollPane.setBorder(null);
        innerPanel.add(aboutScrollPane, gbc);
        Style bold = aboutContent.getStyledDocument().addStyle("bold", null);
        StyleConstants.setBold(bold, true);
        Style italics = aboutContent.getStyledDocument().addStyle("italics", null);
        StyleConstants.setItalic(italics, true);

        try {
            String intro = "Stepper is designed to be a natural evolution of Burp Suite's Repeater tool, " +
                    "providing the ability to create sequences of steps and define regular expressions to extract " +
                    "values from responses which can then be used in subsequent steps.\n\n";
            String instructionsHeader = "Instructions:\n";
            String instructions = "1. Create a new sequence. Double-click the title to set a suitable name.\n" +
                    "2. Optional: Configure the global variables to use for the sequence.\n" +
                    "3. Add your steps to the sequence manually, or using the context menu entry.\n" +
                    "4. Optional: Define variables for steps, providing a regular expression which will " +
                    "be used to extract the values from the response.\n" +
                    "   Tip: You can execute a single step to test your regular expressions using the button in the top right.\n" +
                    "5. Execute the entire sequence using the button at the bottom of the panel.\n\n" +
                    "Steps can be rearranged by right-clicking their tab, and selecting their destination.\n";

            String variableHelpHeader = "Variables:\n";
            String variableHelp = "Variables can be defined for use within a sequence. Variables consist of an " +
                    "identifier and a regular expression, or in the case of initial variables defined in the Globals tab, an identifier and value.\n" +
                    "Step variables, defined with a regular expression, have their values set from the response of the step in which they are defined. " +
                    "The variable is then available for use within the request of subsequent steps after their definition.\n" +
                    "However, Global variables, defined with a literal initial value, can be used throughout the sequence.\n\n" +
                    "Both step and global variables may be updated in later steps after their definition.\n\n";

            String regularExpressionHeader = "Regular Expression Variables:\n";
            String regularExpressionHelp = "Variables which are defined with a regular expression are updated each time " +
                    "the step in which they are defined is executed.\n" +
                    "The regular expression is executed on the response received, with the first match being used as the new value.\n" +
                    "If the defined regular expression has no groups defined, the whole match will be used.\n" +
                    "If the regular expression defines capture groups, the first group will be used.\n" +
                    "If groups are required but should not be used as the value, a non-capturing group may be used. e.g. (?:REGEX)\n\n";
            String regularExpressionExampleHeader = "Example: \n";
            String regularExpressionExample = "Response: \"Hello People, Hello World!\"\n" +
                    "Expression: World|Earth, Result: World\n" +
                    "Expression: Hello (World|Earth)!, Result: World\n" +
                    "Expression: (?:Goodbye|Hello) (World)!, Result: World\n\n";

            String variableInsertion = "To use a variable in a request after it has been defined, either use the " +
                    "option in the context menu to copy the parameter to the clipboard, or manually insert it by " +
                    "including it as below:\n";
            String variableExample = "$VAR:VARIABLE_IDENTIFIER$\n";


//            aboutContent.getDocument().insertString(aboutContent.getText().length(), intro, italics);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), instructionsHeader, bold);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), instructions, null);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), variableHelpHeader, bold);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), variableHelp, null);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), regularExpressionHeader, bold);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), regularExpressionHelp, null);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), regularExpressionExampleHeader, bold);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), regularExpressionExample, null);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), variableInsertion, null);
//            aboutContent.getDocument().insertString(aboutContent.getText().length(), variableExample, italics);
            
            //Doing this an odd way since insertString seems to cause errors on windows!
            int offset = 0;
            String[] sections = new String[]{intro, instructionsHeader, instructions, variableHelpHeader, variableHelp
                    , regularExpressionHeader, regularExpressionHelp, regularExpressionExampleHeader
                    , regularExpressionExample, variableInsertion, variableExample};
            Style[] styles = new Style[]{italics, bold, null, bold, null, bold, null, bold, null, null, italics};
            String content = String.join("", sections);
            aboutContent.setText(content);
            for (int i = 0; i < sections.length; i++) {
                String section = sections[i];
                if(styles[i] != null)
                    aboutContent.getStyledDocument().setCharacterAttributes(offset, section.length(), styles[i], false);
                offset+=section.length();
            }
            


        } catch (Exception e) {
            StringWriter writer = new StringWriter();
            e.printStackTrace(new PrintWriter(writer));
            Stepper.callbacks.printError(writer.toString());
        }

//        aboutContent.getStyledDocument().setParagraphAttributes(3, 3, bold, true);

        //Bottom padding panels
        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 2;
        gbc.gridy = 1;
        gbc.weightx = 0;
        gbc.weighty = 0.9;

        innerPanel.setPreferredSize(new Dimension(900, 800));
        innerPanel.setMinimumSize(new Dimension(500, 300));
        this.add(innerPanel, gbc);

        gbc.weighty = 0.1;
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(new JPanel(), gbc);
        gbc.gridx = 3;
        this.add(new JPanel(), gbc);
    }

    private ImageIcon loadImage(String filename, int width, int height){
        ClassLoader cldr = this.getClass().getClassLoader();
        URL imageURLMain = cldr.getResource(filename);

        if(imageURLMain != null) {
            Image scaled = new ImageIcon(imageURLMain).getImage().getScaledInstance(width, height, Image.SCALE_SMOOTH);
            ImageIcon scaledIcon = new ImageIcon(scaled);
            BufferedImage bufferedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = (Graphics2D) bufferedImage.getGraphics();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.drawImage(scaledIcon.getImage(), null, null);
            return new ImageIcon(bufferedImage);
        }
        return null;
    }
}
