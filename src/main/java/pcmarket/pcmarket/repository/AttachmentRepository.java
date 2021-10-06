package pcmarket.pcmarket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pcmarket.pcmarket.entity.Attachment;

public interface AttachmentRepository extends JpaRepository<Attachment,Integer> {
}
