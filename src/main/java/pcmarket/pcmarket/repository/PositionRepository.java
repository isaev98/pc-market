package pcmarket.pcmarket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import pcmarket.pcmarket.entity.Position;
@RepositoryRestResource(path = "position")
public interface PositionRepository extends JpaRepository<Position,Integer> {
}
