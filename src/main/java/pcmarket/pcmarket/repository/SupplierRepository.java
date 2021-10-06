package pcmarket.pcmarket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import pcmarket.pcmarket.entity.Supplier;
@RepositoryRestResource(path = "supplier")
public interface SupplierRepository extends JpaRepository<Supplier,Integer> {
}
