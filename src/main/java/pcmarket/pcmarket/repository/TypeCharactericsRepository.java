package pcmarket.pcmarket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import pcmarket.pcmarket.entity.TypeCharacterics;

@RepositoryRestResource(path = "typeCharacteristics")
public interface TypeCharactericsRepository extends JpaRepository<TypeCharacterics,Integer> {
}
