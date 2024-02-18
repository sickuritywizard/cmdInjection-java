package org.pradeep;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws Exception {

        // System.out.println("X------- COMMAND INJECTION POC-------X");

        //PROCESS BUILDER
        // insecurePB_DirectInput();
        // insecurePB_DirectInput_SpaceSplit();
        // insecurePB_BinSh_ArgInput();
        // insecurePB_BinSh_Binary_AppendInput();
        // insecurePB_ArgumentInjection_InputSplit();
        // insecurePB_PythonBash_ArgInput();
        // securePB_ArgumentInjection();
        // securePB();

        //RUNTIME
        // insecureRuntime_DirectInput();
        // insecureRuntime_DirectInputSplit();
        // insecureRuntime_ArgumentInjection();
        // secureRuntime();

    }


    private static void syntaxExplained(){
        String userInput = "touch example1";
        //All these 4 Syntax are Same

        //METHOD1: Using constructor ProcessBuilder(String...)
        ProcessBuilder pb1 = new ProcessBuilder("sh", "-c", userInput);

        //METHOD2: Using constructor ProcessBuilder(String[])
        String[] cmdList = new String[] {"sh", "-c", userInput};
        ProcessBuilder pb2 = new ProcessBuilder(cmdList);

        //METHOD3: Using command(String...)
        ProcessBuilder pb3 = new ProcessBuilder();
        pb3.command("sh", "-c", userInput);            //This also overrides if anything was passed in ProcessBuilder("cmd")

        //METHOD4: Using command.add(string)
        ProcessBuilder pb4 = new ProcessBuilder();
        pb4.command().add("/bin/sh");                   //Keeps appending to the list
        pb4.command().add("-c");
        pb4.command().add(userInput);
    }


    //Util to print the ProcessBuilder Command Output
    private static void printProcessBuilderOutput(String methodName,ProcessBuilder pb, Process process) throws IOException,InterruptedException {
        System.out.println("\n" + methodName + "\n" + "-".repeat(methodName.length()));
        System.out.println("|-Command: "+ String.join(" ", pb.command()));
        System.out.print("|-Output : ");

        InputStream inputStream = process.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }

        // Wait for the process to complete
        int exitCode = process.waitFor();
        System.out.println("\n|- Exit Code: " + exitCode);
    }


    private static void insecurePB_DirectInput() throws IOException,InterruptedException {
        String userInput = "whoami";                  //Only single command without space will work
        // String userInput2 = "/bin/touch test";       Error

        ProcessBuilder pb = new ProcessBuilder(userInput);
        Process processInfo = pb.start();
        printProcessBuilderOutput("insecurePB_DirectInput()", pb, processInfo);
    }


    private static void insecurePB_DirectInput_SpaceSplit() throws IOException,InterruptedException {
        String userInput = "touch /tmp/testing/hacker1";        // => [touch, "/tmp/testing/hacker3"]
        String[] cmdList = userInput.split(" ");

        ProcessBuilder pb = new ProcessBuilder(cmdList);
        Process processInfo = pb.start();
        printProcessBuilderOutput("insecurePB_DirectInput_SpaceSplit()", pb, processInfo);
    }


    private static void insecurePB_BinSh_ArgInput() throws IOException,InterruptedException {
        String userInput = "touch /tmp/testing/hacker2";

        ProcessBuilder pb = new ProcessBuilder("sh", "-c", userInput);  //Vuln: Can directly run any command
        Process processInfo = pb.start();
        printProcessBuilderOutput("insecurePB_BinSh_ArgInput()", pb ,processInfo);
    }


    private static void insecurePB_BinSh_Binary_AppendInput() throws IOException,InterruptedException {
        String userInput = "test; touch /tmp/testing/hacker3";

        //Vuln
        ProcessBuilder pb = new ProcessBuilder("/bin/sh","-c", "curl" + userInput);

        //Vuln
        ProcessBuilder pb2 = new ProcessBuilder("/bin/sh","-c", "curl " + userInput);

        ////Safe: As "curl + userInpuy" will be treated as binaryname, errors with program not found
        ProcessBuilder pb3 = new ProcessBuilder("curl " + userInput);

        Process processInfo = pb.start();
        printProcessBuilderOutput("insecurePB_BinSh_Binary_AppendInput()", pb ,processInfo);

    }


    private static void insecurePB_ArgumentInjection_InputSplit() throws IOException,InterruptedException {
        String userInput = "* -exec whoami ;";

        ProcessBuilder pb = new ProcessBuilder("find", "/tmp/testing", "-name");
        // pb.command().add(userInput);                            //Wont work as the entire payload is passed as value to -name arg
        pb.command().addAll(Arrays.asList(userInput.split(" ")));  //Vulnerable

        Process processInfo = pb.start();
        printProcessBuilderOutput("insecurePB_ArgumentInjection_InputSplit()", pb, processInfo);

    }


    private static void insecurePB_PythonBash_ArgInput() throws IOException,InterruptedException {
        String userInput1 = "/tmp/testing/exploit.py";    //Scenario: Exploit Script uploaded via fileupload
        ProcessBuilder pb1 = new ProcessBuilder("/usr/bin/python3",userInput1);
        Process process1 = pb1.start();

        String userInput2 = "/tmp/testing/exploit.sh";    //Scenario: Exploit Script uploaded via fileupload
        ProcessBuilder pb2 = new ProcessBuilder("/bin/sh",userInput2);
        Process process2 = pb2.start();

        // printProcessBuilderOutput("insecurePB_Python_ArgInput()", pb1, process1);
        printProcessBuilderOutput("insecurePB_PythonBash_ArgInput()", pb2, process2);

    }


    private static void securePB_ArgumentInjection() throws IOException,InterruptedException {
        String userInput = "* -exec whoami ;";

        ProcessBuilder pb = new ProcessBuilder("find", "/tmp/testing", "-name");
        pb.command().add(userInput);   //Wont work as the entire payload is passed as value to -name arg

        Process processInfo = pb.start();
        printProcessBuilderOutput("securePB_ArgumentInjection()", pb, processInfo);

    }


    private static void securePB() throws IOException,InterruptedException {
        String userInput = "165.22.219.176:8080; touch /tmp/testing/hacker0";

        //Secure: userInput is passed as argument to curl. Check with Argument Injection
        ProcessBuilder pb = new ProcessBuilder("/usr/bin/curl",userInput);
        Process processInfo = pb.start();

        printProcessBuilderOutput("securePB()",pb , processInfo);
    }



    //RUNTIME.EXEC

    private static void printRuntimeOutput(String methodName, Process process) throws IOException,InterruptedException{
        System.out.println("\n" + methodName + "\n" + "-".repeat(methodName.length()));
        System.out.print("|-Output : ");

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }

        // Wait for the process to complete
        int exitCode = process.waitFor();
        System.out.println("|- Exit Code: " + exitCode);

    }


    private static void insecureRuntime_DirectInput() throws IOException,InterruptedException {
        String userInput = "touch /tmp/testing/xhacker1";
        String exploitPayload = "sh -c $@|sh . touch /tmp/testing/xhacker2";    //Vuln
        Process process = Runtime.getRuntime().exec(userInput);                //userInput is automatically split on the spaces, userInput[0]=program and rest as Args
        printRuntimeOutput("insecureRuntime_DirectInput()", process);
    }


    private static void insecureRuntime_DirectInputSplit() throws IOException,InterruptedException {
        String userInput = "touch /tmp/testing/xhacker2";
        String[] cmdArgs = userInput.split(" ");                //Same as String[] cmdArgs = {"touch", "/tmp/testing/xhacker2"};
        Process process2 = Runtime.getRuntime().exec(cmdArgs);
        printRuntimeOutput("insecureRuntime_DirectInputSplit()", process2);

    }


    private static void insecureRuntime_ArgumentInjection() throws IOException,InterruptedException {
        // String userInput = "test ; whoami";     //This won't work as it will go as arg to find
        String userInput  = "* -exec whoami ;";    //Argument Injection
        Process process = Runtime.getRuntime().exec("find /tmp/testing -name " + userInput);

        // Process process = Runtime.getRuntime().exec("find /tmp/testing -name " , userInput);    //Invalid Syntax: Takes only string or list
        printRuntimeOutput("insecureRuntime_ArgumentInjection()", process);
    }


    private static void secureRuntime() throws IOException,InterruptedException {
        // 0)Avoid using Runtime or ProcessBuilder if possible
        // 1)Sanitize the Input
        // 2)Whitelist Command
        // 3)Use ProcessBuilder() as it parses entire userInput as single command
    }


}