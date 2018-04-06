package com.csaa.lyft.web;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value="/logs")
public class LogController {
	
	Logger log= Logger.getLogger(LogController.class);
	
    @RequestMapping(method={RequestMethod.GET}, headers="Accept=application/json")
    public Map<String,String> getlogs() throws Exception {
        
        Map<String, String> logFiles = new HashMap<String, String>();
        String logDir = "C:\\Users\\grvjaya\\AAA\\server\\apache-tomcat-7.0.53\\logs";

        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get(logDir))) {
    		for (Path path: directoryStream) {
    			logFiles.put(path.getFileName().toString(), path.toString());
    		}
        }catch (IOException e) {
        	e.printStackTrace();
    	}
        
        return logFiles;
        
    }
   
}
