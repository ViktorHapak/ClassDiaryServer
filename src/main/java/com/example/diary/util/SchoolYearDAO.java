package com.example.diary.util;

import com.example.diary.models.SchoolYear;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.time.LocalDate;

@Component
@Service
public class SchoolYearDAO {

    public SchoolYear getSchoolYearObject() throws IOException {
        //return objectMapper().readValue(new File("src/main/resources/data.json"), SchoolYear.class);

        RandomAccessFile file = new RandomAccessFile("src/main/resources/data.txt","r");
        String s = file.readLine();
        file.close();
        return new SchoolYear(1, s);

    }

    public SchoolYear defineSchoolYear(){
        int year;
        if(LocalDate.now().getMonthValue()<9) year = LocalDate.now().getYear() -1;
        else year = LocalDate.now().getYear();

        int nextYear = year + 1;
        return new SchoolYear(1,year + "/" + nextYear);
    }

    public void rewriteSchoolYear(SchoolYear schoolYear){
        RandomAccessFile file1 = null;
        try {
            file1 = new RandomAccessFile("src/main/resources/data.txt","rw");
            file1.writeBytes(schoolYear.getYear());
            file1.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
