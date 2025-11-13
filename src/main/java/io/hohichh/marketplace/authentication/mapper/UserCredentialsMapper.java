package io.hohichh.marketplace.authentication.mapper;

import io.hohichh.marketplace.authentication.model.UserCredentials;
import io.hohichh.marketplace.authentication.dto.UserCredentialsCreateDto;
import io.hohichh.marketplace.authentication.dto.UserCredentialsResponseDto;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserCredentialsMapper {


    @Mapping(target = "id", ignore = true)
    @Mapping(target = "passwordHash", ignore = true)
    @Mapping(target = "role", ignore = true)
    UserCredentials toEntity(UserCredentialsCreateDto createDto);


    @Mapping(source = "role.roleName", target = "roleName")
    UserCredentialsResponseDto toResponseDto(UserCredentials entity);
}