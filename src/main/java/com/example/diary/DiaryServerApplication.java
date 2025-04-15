package com.example.diary;


import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.ssl.SslProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.io.IOException;

@SpringBootApplication
public class DiaryServerApplication {


	public static void main(String[] args) throws IOException {
		SpringApplication.run(DiaryServerApplication.class, args);
	}

	@Bean
	public ModelMapper modelMapper(){
		return new ModelMapper();
	}

	/*@Bean
	public ObjectMapper objectMapper(){ return new ObjectMapper(); }*/



}
