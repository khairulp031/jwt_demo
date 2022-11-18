package com.example.jwt_demo.services;

import com.example.jwt_demo.utils.PublicKeyReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/simple/v1")
public class Simple {


    @GetMapping()
    String getsimple(@RequestHeader("authorization") String authorization) throws Exception {
        if (PublicKeyReader.verify(authorization.replace("Bearer ",""))) {
            return PublicKeyReader.getPayload(authorization.replace("Bearer ",""));
        } else {
            return  PublicKeyReader.errorMsg;
        }
    }
}
