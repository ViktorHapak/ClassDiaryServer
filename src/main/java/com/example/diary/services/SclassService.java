package com.example.diary.services;

import com.example.diary.models.Sclass;
import com.example.diary.models.Subject;
import com.example.diary.repositories.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class SclassService {

    @Autowired
    private SclassRepository sclassRepository;

    @Autowired
    private TeacherRegistryRepository teacherRegistryRepository;

    @Autowired
    private Grades1Repository grades1Repository;

    @Autowired
    private Grades2Repository grades2Repository;

    @Autowired
    private FinalGradesRepository finalGradesRepository;

    @Autowired
    private StudentRepository studentRepository;

    public Sclass find(Integer id){
        return sclassRepository.findById(id).orElseThrow(RuntimeException::new);
    }

    public Sclass findByName(String name) {return sclassRepository.findByName(name).orElseThrow(RuntimeException::new);}

    public List<Sclass> findAll(){return sclassRepository.findAll();}

    public List<Sclass> findBySubject(Subject subject) {
        return teacherRegistryRepository.findBySubject(subject).stream().map(e ->
                e.getSclass()).distinct().collect(Collectors.toList());
    }


    //Új osztály hozzáadása az évfolyamhoz (A,B,C alapján)
    @Transactional
    public String addClass(int year){

        if (year<1 || year>8) throw new RuntimeException("Érvényes évfolyamot adjon meg!");

        List<Character> markings = sclassRepository.findByYear(year).stream().map(item ->
        item.getMarking()).collect(Collectors.toList());

        if(markings.isEmpty()){
            Sclass sclass = new Sclass(year, 'A', "" + year + 'A');
            sclassRepository.save(sclass);
            return "" + year + 'A';
        } else {
            List<Integer> asciiList = (markings.stream().map(item -> (int)item).collect(Collectors.toUnmodifiableList()));
            List<Integer> sortedAsciiList = asciiList.stream().sorted().collect(Collectors.toUnmodifiableList());

            int maxNumber = sortedAsciiList.get(sortedAsciiList.size()-1);

            char newMarking = (char) (maxNumber + 1);

            Sclass sclass = new Sclass(year, newMarking, "" + year + newMarking);
            sclassRepository.save(sclass);
            return "" + year + newMarking;
        }

    }

    //Osztály törlésekor az évfolyam többi osztályának a jelölése is változik
    @Transactional
    public int deleteClass(Sclass sclass){
        int year = sclass.getYear();
        char marking = sclass.getMarking();


        //Keressük meg a törlendő osztálynál nagyobb jelölésű osztályokat az évfolyamról:
        List<Integer> idListGreater = (sclassRepository.findByYear(year).stream().filter(
                item -> (int)item.getMarking() > (int)marking).collect(Collectors.toUnmodifiableList()))
                .stream().map(item -> item.getId()).collect(Collectors.toUnmodifiableList());

        //Csökkentsük ezen osztályok jelölését ASCII-kód használatával:
        for(Integer id: idListGreater){
            Sclass sclass1 = sclassRepository.findById(id).orElseThrow(RuntimeException::new);
            sclass1.setMarking((char)((int)sclass1.getMarking()-1));
            sclass1.setName(sclass.getYear() + "" + (char)((int)sclass1.getMarking()) + "");

            sclassRepository.save(sclass1);
        }

        //Ekkor tanulók maradhatnak osztály nélkül, valamint a tanári bejegyzéseket is törölnünk kell:
        int number = (int)sclass.getStudents().stream().count();
        studentRepository.findBySclass(sclass).stream().forEach(e->{
            e.setSclass(null);
            studentRepository.save(e);
        });

        teacherRegistryRepository.deleteAll(teacherRegistryRepository.findBySclass(sclass));
        sclassRepository.delete(sclass);


        return number;
    }

    @Transactional
    public void increaseYear(){
        sclassRepository.findAll().stream().forEach(e -> {
            if(e.getYear() == 8) {
                studentRepository.deleteAll(studentRepository.findBySclass(e));
                sclassRepository.delete(e);}
            else {
                e.setYear(e.getYear() + 1);
                e.setName(e.getYear() + "" + e.getMarking());
            }
            sclassRepository.save(e);
        });
    }
}
