package com.mska.spring.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.mska.spring.dto.Facultad;

@Repository
public interface FacultadDAO extends JpaRepository<Facultad, Long>{

	/**
	 * Se heredan los métodos CRUD básicos de la clase JpaRepository se utiliza un
	 * Integer como parámetro para la entidad Facultad.
	 */
}
