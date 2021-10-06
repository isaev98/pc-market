package pcmarket.pcmarket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import pcmarket.pcmarket.entity.Type;
@RepositoryRestResource(path = "type")
public interface TypeRepository extends JpaRepository<Type,Integer> {
}
