package com.example.diary;

import com.example.diary.models.SchoolYear;
import com.example.diary.services.GradesService;
import com.example.diary.services.SclassService;
import com.example.diary.services.SubjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.time.LocalDate;


@Component
@Service
public class ChangeSchoolYear{


    //@Bean
    public SchoolYear schoolYearObject() throws IOException {
        //return objectMapper().readValue(new File("src/main/resources/data.json"), SchoolYear.class);

        RandomAccessFile file = new RandomAccessFile("src/main/resources/data.txt","r");
        String s = file.readLine();
        file.close();
        return new SchoolYear(1, s);

    }

    private String defineSchoolYear(){
        int year;
        if(LocalDate.now().getMonthValue()<9) year = LocalDate.now().getYear() -1;
        else year = LocalDate.now().getYear();

        int nextYear = year + 1;
        return year + "/" + nextYear;

    }


}
