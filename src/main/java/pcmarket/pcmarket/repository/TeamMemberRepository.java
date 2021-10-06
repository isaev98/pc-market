package pcmarket.pcmarket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import pcmarket.pcmarket.entity.TeamMember;
@RepositoryRestResource(path = "teamMember")
public interface TeamMemberRepository extends JpaRepository<TeamMember,Integer> {
}
